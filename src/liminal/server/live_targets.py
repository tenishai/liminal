"""Live targets — federated HTTP targets added, replaced and removed through the
admin plane, no config file edit, no redeploy (liminal#222).

``targets.toml`` stays the seed: it is read at boot and its targets are the
file's to change. A live target is a row in the policy database (the same
volume the grants live on), applied to the running ``Multiplexer`` the moment
``PUT /admin/targets/{name}`` is accepted and brought back at the next boot.
The rules:

- A live target may not take a name an in-process handler or a file target
  holds (``FileOwned``, 409 at the API; skipped with a warning at boot, so a
  later config file change can never crash the gateway on a stored row).
- Secrets never travel in the spec: ``bearer_token`` is refused; credentials
  are env variable names (``bearer_token_env``, ``catalog_headers_env``) or
  come per call from the credential resolver (``service-token``,
  ``service-headers``). Only ``transport = "http"`` is served live.
- A replacement is started first and then takes the name; the old target is
  shut down after. A target whose startup fails is still registered and reads
  degraded on ``/healthz``, the same posture file targets have (#86), so the
  operator sees it rather than a silently missing surface.
- Scope rules (``required_scope``, ``tool_scopes``) of a live target are
  enforced like a file target's: ``scope_for`` consults the live specs first
  and falls back to the static map built at ``create_app``.

The admin app and the data-plane app may be two listeners in one process
(``--admin-port``); they share one ``LiveTargets`` object, which is why the
controller is built by the CLI and handed to both.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from collections.abc import Callable
from typing import Any

import httpx
import structlog

from liminal.server.scopes import DENY_SCOPE
from liminal.target.base import Target
from liminal.target.config import TargetConfigError, TargetSpec, load_target_specs
from liminal.target.http import HttpTarget

log = structlog.get_logger(__name__)

# Spec keys that would carry a secret inline. A live spec names env variables
# instead, so a secret is never in a request body, a log line or the database.
SECRET_KEYS = frozenset({"bearer_token"})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS live_targets (
    name        TEXT PRIMARY KEY,
    spec        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class LiveTargetError(ValueError):
    """A live-target request the gateway refuses; str() is the sentence."""


class FileOwned(LiveTargetError):
    """The name belongs to an in-process handler or a ``targets.toml`` target."""


class UnknownLiveTarget(LiveTargetError):
    """No live target of that name."""


class LiveTargetStore:
    """The ``live_targets`` table: name -> spec body (the ``[[target]]`` keys
    minus ``name``), in the policy database."""

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def list(self) -> list[tuple[str, dict[str, Any]]]:
        rows = self._conn.execute("SELECT name, spec FROM live_targets ORDER BY name").fetchall()
        return [(r["name"], json.loads(r["spec"])) for r in rows]

    def put(self, name: str, spec: dict[str, Any]) -> None:
        now = _now_iso()
        self._conn.execute(
            "INSERT INTO live_targets(name, spec, created_at, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET spec = excluded.spec, updated_at = excluded.updated_at",
            (name, json.dumps(spec, sort_keys=True), now, now),
        )
        self._conn.commit()

    def delete(self, name: str) -> bool:
        cur = self._conn.execute("DELETE FROM live_targets WHERE name = ?", (name,))
        self._conn.commit()
        return cur.rowcount > 0

    def close(self) -> None:
        self._conn.close()


class LiveTargets:
    """The controller: validates, persists and applies live targets to the
    multiplexer it is attached to. One per process, shared by both apps."""

    def __init__(
        self,
        store: LiveTargetStore,
        *,
        http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
    ) -> None:
        self._store = store
        self._http_client_factory = http_client_factory
        self._dispatcher: Any = None
        self._reserved: set[str] = set()
        self._file_names: list[str] = []
        self._scope_fallback: Callable[[str], str | None] = lambda _name: None
        self._specs: dict[str, TargetSpec] = {}
        self._bodies: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    # ---- wiring -----------------------------------------------------------

    def attach(
        self,
        dispatcher: Any,
        *,
        reserved: set[str],
        file_specs: list[TargetSpec] = (),
        scope_fallback: Callable[[str], str | None],
    ) -> None:
        """Called by ``create_app`` once the multiplexer exists. ``reserved``
        are the names a live target may not take (handlers + file targets)."""
        self._dispatcher = dispatcher
        self._reserved = set(reserved)
        self._file_names = [s.name for s in file_specs]
        self._scope_fallback = scope_fallback

    @property
    def attached(self) -> bool:
        return self._dispatcher is not None

    # ---- the API ----------------------------------------------------------

    def spec_for(self, name: str, body: dict[str, Any]) -> TargetSpec:
        """Validate a request body as the ``[[target]]`` it stands for."""
        if not isinstance(body, dict):
            raise LiveTargetError("the target spec must be an object of [[target]] keys")
        if "name" in body and body["name"] != name:
            raise LiveTargetError(f"the body names {body['name']!r} but the path names {name!r}")
        leaked = sorted(k for k in body if k in SECRET_KEYS)
        if leaked:
            raise LiveTargetError(
                f"a live target carries no secret: {leaked} must be env variable names "
                "(bearer_token_env, catalog_headers_env) or per-call credentials"
            )
        data = {k: v for k, v in body.items() if k != "name"}
        try:
            spec = load_target_specs([{"name": name, **data}])[0]
        except TargetConfigError as exc:
            raise LiveTargetError(str(exc)) from exc
        if spec.transport != "http":
            raise LiveTargetError("only transport = \"http\" targets can be added live")
        return spec

    async def put(self, name: str, body: dict[str, Any]) -> str:
        """Validate, persist and apply. Returns the target's status
        (``"ready"`` or the degraded text) once it has been started."""
        self._require_attached()
        if name in self._reserved:
            raise FileOwned(
                f"target {name!r} belongs to the gateway's configuration (a handler or a "
                "targets.toml entry); change it there"
            )
        spec = self.spec_for(name, body)
        async with self._lock:
            status = await self._start(spec)
            self._store.put(name, {k: v for k, v in body.items() if k != "name"})
            self._bodies[name] = {k: v for k, v in body.items() if k != "name"}
            return status

    async def delete(self, name: str) -> None:
        self._require_attached()
        if name in self._reserved:
            raise FileOwned(
                f"target {name!r} belongs to the gateway's configuration; remove it there"
            )
        async with self._lock:
            old = self._dispatcher.remove_target(name)
            stored = self._store.delete(name)
            self._specs.pop(name, None)
            self._bodies.pop(name, None)
            if old is None and not stored:
                raise UnknownLiveTarget(f"no live target {name!r}")
            if old is not None:
                await self._shutdown_quietly(old)
            log.info("live_targets.removed", target=name)

    def list(self) -> list[dict[str, Any]]:
        """Every target the gateway serves: live ones with their spec, file
        ones by name (their spec lives in the config file)."""
        out: list[dict[str, Any]] = []
        statuses = self._statuses()
        for name in self._file_names:
            out.append({"name": name, "source": "file", "status": statuses.get(name, "ready")})
        for name in sorted(self._bodies):
            out.append({
                "name": name, "source": "live", "status": statuses.get(name, "not started"),
                "spec": dict(self._bodies[name]),
            })
        return out

    async def load_at_boot(self) -> None:
        """Bring every stored target back. A row whose name a handler or file
        target now holds is skipped with a warning, never a boot failure."""
        self._require_attached()
        for name, body in self._store.list():
            if name in self._reserved:
                log.warning(
                    "live_targets.shadowed_by_config", target=name,
                    msg="a handler or targets.toml entry holds this name; the stored row is left alone",
                )
                continue
            try:
                spec = self.spec_for(name, body)
            except LiveTargetError as exc:
                log.error("live_targets.stored_spec_invalid", target=name, error=str(exc)[:200])
                continue
            async with self._lock:
                status = await self._start(spec)
                self._bodies[name] = dict(body)
            log.info("live_targets.loaded", target=name, status=status)

    def scope_for(self, name: str) -> str | None:
        """The ``policy_scope_for`` resolver with live targets in front: the
        same per-tool, then target-level, then deny-by-default rule the static
        map applies (app.scope_for), then the static map itself."""
        prefix = name.split(".", 1)[0]
        spec = self._specs.get(prefix)
        if spec is None:
            return self._scope_fallback(name)
        _, _, tool = name.partition(".")
        if tool and tool in spec.tool_scopes:
            return spec.tool_scopes[tool]
        if spec.required_scope:
            return spec.required_scope
        if spec.tool_scopes:
            return DENY_SCOPE
        return None

    # ---- internals --------------------------------------------------------

    def _require_attached(self) -> None:
        if self._dispatcher is None:
            raise LiveTargetError("live targets are not attached to a running gateway")

    def _statuses(self) -> dict[str, str]:
        failed = getattr(self._dispatcher, "startup_failures", {})
        out: dict[str, str] = {}
        for name, target in self._dispatcher.targets.items():
            out[name] = failed.get(name) or getattr(target, "catalog_status", "ready")
        return out

    async def _start(self, spec: TargetSpec) -> str:
        """Build and start the target, then let it take the name; the one it
        replaces is shut down after. Returns the status to report."""
        kwargs: dict[str, Any] = {}
        if self._http_client_factory is not None:
            kwargs["http_client"] = self._http_client_factory()
        target: Target = HttpTarget(spec, **kwargs)
        status = "ready"
        try:
            await target.startup()
            status = getattr(target, "catalog_status", "ready")
        except Exception as exc:  # noqa: BLE001 -- reported, never raised past the API
            status = "startup failed"
            log.error(
                "live_targets.startup_failed", target=spec.name,
                error_type=type(exc).__name__, error=str(exc)[:200],
            )
        old = self._dispatcher.add_target(target)
        if status == "startup failed":
            self._dispatcher.startup_failures[spec.name] = status
        self._specs[spec.name] = spec
        if old is not None:
            await self._shutdown_quietly(old)
        log.info("live_targets.applied", target=spec.name, status=status, replaced=old is not None)
        return status

    @staticmethod
    async def _shutdown_quietly(target: Target) -> None:
        try:
            await target.shutdown()
        except Exception as exc:  # noqa: BLE001
            log.warning("live_targets.shutdown_failed", target=target.name, error=str(exc)[:200])


__all__ = ["FileOwned", "LiveTargetError", "LiveTargetStore", "LiveTargets", "SECRET_KEYS", "UnknownLiveTarget"]
