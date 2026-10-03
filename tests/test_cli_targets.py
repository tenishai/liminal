"""#15 — declarative, versioned config-driven targets.

Tests for ``--targets`` TOML loading on the ``liminal serve`` subcommand.

Strategy: most tests exercise ``_load_targets_file`` directly (it is the
unit-testable seam that all error paths flow through). One integration test
builds an app via ``create_app`` and asserts the Multiplexer/dispatcher has
the configured target by name — the same approach the existing
``test_cli_serve_wiring.py`` uses for the trust-registry helper.

ASGITransport tests do NOT run lifespan, so http targets won't connect to a
live upstream — we assert on the parsed ``TargetSpec`` and dispatcher
registration, not on a live call round-trip.
"""

from __future__ import annotations

import pytest

from liminal.cli import SUPPORTED_CONFIG_VERSION, _load_targets_file
from liminal.target.config import TargetConfigError, TargetSpec

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _write_targets(tmp_path, content: str):
    """Write a targets TOML file and return its path string."""
    p = tmp_path / "targets.toml"
    p.write_text(content, encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# 1. Common-case: two-key http target (the headline path)
# ---------------------------------------------------------------------------


def test_common_case_http_target_loads(tmp_path) -> None:
    """The minimal two-key http target must produce a valid TargetSpec with
    defaults applied (transport=http, trust=untrusted, identity=none, etc.)."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "jira"\naddress = "https://jira-mcp.internal/mcp"\n',
    )
    specs = _load_targets_file(path)
    assert len(specs) == 1
    spec = specs[0]
    assert isinstance(spec, TargetSpec)
    assert spec.name == "jira"
    assert spec.transport == "http"
    assert spec.address == "https://jira-mcp.internal/mcp"
    # defaults
    assert spec.trust == "untrusted"
    assert spec.identity == "none"
    assert spec.on_untrusted == "flag"
    assert spec.auth_method == "none"


def test_multiple_targets_load(tmp_path) -> None:
    """Multiple ``[[target]]`` tables all parse correctly."""
    content = (
        "config_version = 1\n\n"
        "[[target]]\n"
        'name = "jira"\n'
        'address = "https://jira-mcp.internal/mcp"\n\n'
        "[[target]]\n"
        'name = "github"\n'
        'address = "https://github-mcp.internal/mcp"\n'
        'trust = "trusted"\n'
    )
    path = _write_targets(tmp_path, content)
    specs = _load_targets_file(path)
    assert len(specs) == 2
    names = {s.name for s in specs}
    assert names == {"jira", "github"}


# ---------------------------------------------------------------------------
# 2. config_version handling
# ---------------------------------------------------------------------------


def test_config_version_absent_warns_but_succeeds(tmp_path, capsys) -> None:
    """A file without config_version succeeds (defaults to 1) but prints a
    stderr warning recommending the operator pin the version."""
    path = _write_targets(
        tmp_path,
        '[[target]]\nname = "jira"\naddress = "https://jira/mcp"\n',
    )
    specs = _load_targets_file(path)
    assert len(specs) == 1
    captured = capsys.readouterr()
    assert "config_version" in captured.err
    assert "warning" in captured.err.lower()


def test_config_version_1_accepted(tmp_path) -> None:
    """config_version = 1 is the supported version and must be accepted silently."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "jira"\naddress = "https://jira/mcp"\n',
    )
    specs = _load_targets_file(path)
    assert len(specs) == 1


def test_config_version_unsupported_raises(tmp_path) -> None:
    """config_version != SUPPORTED_CONFIG_VERSION must raise ValueError (No Silent Failures).

    The caller (main()) catches this and exits 2.
    """
    path = _write_targets(
        tmp_path,
        'config_version = 2\n\n[[target]]\nname = "jira"\naddress = "https://jira/mcp"\n',
    )
    with pytest.raises(ValueError, match="config_version"):
        _load_targets_file(path)


def test_config_version_constant_is_1() -> None:
    """Lock in the constant value so it can't drift by accident."""
    assert SUPPORTED_CONFIG_VERSION == 1


# ---------------------------------------------------------------------------
# 3. Malformed [[target]] → TargetConfigError / ValueError, not silent pass
# ---------------------------------------------------------------------------


def test_unknown_key_raises(tmp_path) -> None:
    """A [[target]] with an unknown key must raise — CLAUDE.md: No Silent Failures.
    A typo like ``addres`` must not silently no-op."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "jira"\naddres = "https://jira/mcp"\n',
    )
    with pytest.raises((ValueError, TargetConfigError), match="unknown key"):
        _load_targets_file(path)


def test_removed_relevance_signals_key_raises(tmp_path) -> None:
    """relevance_signals was removed (liminal#116); a config still setting it must
    fail loudly rather than be silently ignored."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "jira"\naddress = "https://jira/mcp"\n'
        'relevance_signals = ["tickets"]\n',
    )
    with pytest.raises((ValueError, TargetConfigError), match="unknown key"):
        _load_targets_file(path)


def test_http_missing_address_raises(tmp_path) -> None:
    """An http target with no address must be rejected."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "jira"\ntransport = "http"\n',
    )
    with pytest.raises((ValueError, TargetConfigError), match="address"):
        _load_targets_file(path)


def test_stdio_with_identity_forward_raises(tmp_path) -> None:
    """stdio + identity='forward' violates the hard constraint from #13/#12:
    stdio children discard per-request headers. Must be rejected loudly."""
    path = _write_targets(
        tmp_path,
        (
            "config_version = 1\n\n"
            "[[target]]\n"
            'name = "pdftools"\n'
            'transport = "stdio"\n'
            'command = ["npx", "-y", "@vendor/pdf-mcp"]\n'
            'identity = "forward"\n'
        ),
    )
    with pytest.raises((ValueError, TargetConfigError)):
        _load_targets_file(path)


def test_stdio_with_service_token_raises(tmp_path) -> None:
    """stdio + auth_method='service-token' must also be rejected (per-call
    credential headers don't reach stdio children)."""
    path = _write_targets(
        tmp_path,
        (
            "config_version = 1\n\n"
            "[[target]]\n"
            'name = "pdftools"\n'
            'transport = "stdio"\n'
            'command = ["npx", "-y", "@vendor/pdf-mcp"]\n'
            'auth_method = "service-token"\n'
            'credential_key = "PDF_TOKEN"\n'
        ),
    )
    with pytest.raises((ValueError, TargetConfigError)):
        _load_targets_file(path)


# ---------------------------------------------------------------------------
# 4. Targets reach create_app / dispatcher
# ---------------------------------------------------------------------------


def test_targets_reach_dispatcher(tmp_path, keyset, registry) -> None:
    """Targets parsed from a TOML file must reach the Multiplexer when wired
    through create_app(targets=...).

    We assert the dispatcher knows the target by name — not a live call
    (ASGITransport tests don't run lifespan, so http targets won't connect).
    """
    from liminal.server import StaticKeySetVerifier, create_app

    specs = _load_targets_file(
        _write_targets(
            tmp_path,
            'config_version = 1\n\n[[target]]\nname = "jira"\naddress = "https://jira-mcp.internal/mcp"\n',
        )
    )
    assert len(specs) == 1

    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=registry,
        targets=specs,
    )

    # The dispatcher (Multiplexer) holds targets by name in a dict keyed by name.
    dispatcher = app.state.dispatcher
    target_names = set(dispatcher.targets.keys())
    assert "jira" in target_names, f"expected 'jira' in {target_names}"


def test_main_returns_2_for_unsupported_config_version(tmp_path, monkeypatch) -> None:
    """main() must return 2 (exit 2) when the targets file has an unsupported
    config_version — before reaching uvicorn.run."""
    path = _write_targets(
        tmp_path,
        'config_version = 99\n\n[[target]]\nname = "jira"\naddress = "https://jira/mcp"\n',
    )

    # Prevent uvicorn from actually starting if the version check somehow passes.
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)

    from liminal.cli import main

    rc = main(["serve", "--targets", path])
    assert rc == 2, f"expected exit code 2, got {rc}"


def test_main_returns_2_for_malformed_target(tmp_path, monkeypatch) -> None:
    """main() must return 2 when the targets file has a validation error."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "jira"\ntransport = "http"\n',  # missing address
    )

    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)

    from liminal.cli import main

    rc = main(["serve", "--targets", path])
    assert rc == 2, f"expected exit code 2, got {rc}"


# ---------------------------------------------------------------------------
# Prudence #30 review: loud top-level typos + build-time errors return 2
# ---------------------------------------------------------------------------


def test_top_level_unknown_key_raises(tmp_path) -> None:
    """A mistyped table-array (`[[targets]]`) or stray top-level key is a loud
    error, not a silent zero-target run."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[targets]]\nname = "jira"\naddress = "https://jira/mcp"\n',
    )
    with pytest.raises(ValueError, match="unknown top-level key"):
        _load_targets_file(path)


def test_config_version_float_rejected(tmp_path) -> None:
    """config_version = 1.0 (a TOML float) must not slip the integer gate."""
    path = _write_targets(
        tmp_path,
        'config_version = 1.0\n\n[[target]]\nname = "jira"\naddress = "https://jira/mcp"\n',
    )
    with pytest.raises(ValueError, match="not supported"):
        _load_targets_file(path)


def test_zero_targets_warns(tmp_path, capsys) -> None:
    """A file with no [[target]] tables loads [] but warns (explicit intent)."""
    path = _write_targets(tmp_path, "config_version = 1\n")
    specs = _load_targets_file(path)
    assert specs == []
    assert "0 targets" in capsys.readouterr().err


def test_main_returns_2_for_name_collision(tmp_path, monkeypatch) -> None:
    """A --targets name colliding with an in-process handler must be a clean
    exit 2 (via create_app/build_http_targets), not an uncaught traceback."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    # "memory" is a built-in entry-point handler → name collision.
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "memory"\naddress = "https://x/mcp"\n',
    )
    assert main(["serve", "--targets", path]) == 2


def test_single_table_target_typo_hints(tmp_path) -> None:
    """A single ``[target]`` table (instead of the array ``[[target]]``) exits
    loudly with a hint, not a cryptic downstream error."""
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[target]\nname = "jira"\naddress = "https://jira/mcp"\n',
    )
    with pytest.raises(ValueError, match=r"\[\[target\]\]"):
        _load_targets_file(path)


def test_main_returns_2_for_stdio_target(tmp_path, monkeypatch) -> None:
    """A well-formed stdio target (valid config, but not served until Stage B)
    must exit 2 with a diagnostic, not a traceback — the docs list stdio."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "pdf"\ntransport = "stdio"\ncommand = ["npx", "pdf-mcp"]\n',
    )
    assert main(["serve", "--targets", path]) == 2


# ---------------------------------------------------------------------------
# static headers (liminal#130)
# ---------------------------------------------------------------------------


def test_toml_headers_table_loads(tmp_path) -> None:
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "gh"\naddress = "https://gh.example"\n\n'
        '[target.headers]\nX-MCP-Readonly = "true"\n',
    )
    assert _load_targets_file(path)[0].headers == {"X-MCP-Readonly": "true"}


def test_toml_reserved_header_is_refused(tmp_path) -> None:
    path = _write_targets(
        tmp_path,
        'config_version = 1\n\n[[target]]\nname = "gh"\naddress = "https://gh.example"\n\n'
        '[target.headers]\nauthorization = "Bearer x"\n',
    )
    with pytest.raises(ValueError, match="headers may not set"):
        _load_targets_file(path)
