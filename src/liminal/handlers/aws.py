"""aws — read-only AWS calls through a role an account owner granted the gateway.

No access key anywhere. The owner creates one IAM role per connected account
(tenishai/cloud-access: `KoboAccess-Role`, read-only packs) whose trust policy
names the gateway's own Google service account through OIDC. Per call the
gateway mints a Google ID token for itself, trades it for a one-hour session
with `AssumeRoleWithWebIdentity`, names the session after the agent (`kobo-<agent>`,
which CloudTrail records in the assumed-role ARN, so it says which agent did
what; that API takes no SourceIdentity), and runs the
requested read with it. Sessions are cached per (account, agent).

Which accounts exist is operator config in the trust registry, read from
``ctx.extra["aws.roles"]``::

    [tool_extras."aws.roles".aws]
    role_arn = "arn:aws:iam::123456789012:role/KoboAccess-Role"
    audience = "sts.amazonaws.com"      # optional; must match the role's aud condition

Which accounts an agent may reach follows its grant: ``<account>:read`` in
``ctx.granted_scopes`` (the lane kobo writes). Without a grant (single-cabal or
auth-off) every configured account is reachable; the role's trust policy is
still the wall.

Two walls on top of the role's own packs, so a mis-scoped role cannot turn the
gateway into a data exfiltration path: only read verbs are forwarded, and a
short list of data-plane reads (object bodies, secret values, parameter values,
table rows, queue messages) is refused by name.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import anyio
import httpx
import structlog

from liminal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)

EXTRAS_KEY = "aws.roles"
DEFAULT_AUDIENCE = "sts.amazonaws.com"
DEFAULT_REGION = "us-east-1"
SESSION_SECONDS = 3600
# Re-assume this long before the cached session expires.
_REFRESH_MARGIN = 300
_MAX_RESULT_CHARS = 200_000

METADATA_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)
# A file holding an already-minted token (a projected token, or a test): read
# instead of asking the metadata server. Its audience is whatever it carries.
TOKEN_FILE_ENV = "LIMINAL_AWS_WEB_IDENTITY_TOKEN_FILE"

_ROLE_ARN = re.compile(r"^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+$")
# RoleSessionName: [\w+=,.@-], 2..64 chars.
_SESSION_NAME_BAD = re.compile(r"[^\w+=,.@-]")

READ_VERBS = (
    "Get", "List", "Describe", "Lookup", "Search", "Query", "Scan", "Head", "BatchGet",
    "Check", "Count", "Estimate", "Filter", "Preview", "Simulate", "Test", "Validate",
    "Verify", "Discover", "Detect", "Select", "Retrieve", "View",
)
# Read verbs that return data, not configuration. Refused whatever the role allows.
DATA_READS = frozenset({
    ("s3", "GetObject"), ("s3", "SelectObjectContent"), ("s3", "GetObjectTorrent"),
    ("secretsmanager", "GetSecretValue"), ("secretsmanager", "BatchGetSecretValue"),
    ("ssm", "GetParameter"), ("ssm", "GetParameters"), ("ssm", "GetParametersByPath"),
    ("kms", "Decrypt"), ("kms", "GetPublicKey"),
    ("dynamodb", "GetItem"), ("dynamodb", "BatchGetItem"), ("dynamodb", "Query"),
    ("dynamodb", "Scan"), ("dynamodb", "ExecuteStatement"),
    ("sqs", "ReceiveMessage"), ("kinesis", "GetRecords"), ("lambda", "GetFunction"),
    ("rds-data", "ExecuteStatement"), ("redshift-data", "GetStatementResult"),
    ("athena", "GetQueryResults"), ("timestream-query", "Query"),
})

CARD = {
    "handler": "aws",
    "required_scope": "aws:read",
    "description": "Read-only AWS calls through a role the account owner granted the gateway",
    "tools": [
        {"name": "whoami", "description": "Which AWS account and role this agent reaches."},
        {
            "name": "call",
            "description": "Run one read-only AWS API action and return its response.",
        },
    ],
    "activation": "always",
    "credential_keys": [],
    "labels": {"tier": "builtin", "cloud": "aws"},
}


class AwsError(Exception):
    """A refusal or failure the agent can act on, in one sentence."""


@dataclass(frozen=True, slots=True)
class RoleSpec:
    integration: str
    role_arn: str
    audience: str = DEFAULT_AUDIENCE

    @property
    def account(self) -> str:
        return self.role_arn.split(":")[4]


@dataclass(slots=True)
class AwsSession:
    access_key: str
    secret_key: str
    token: str
    expires_at: float
    assumed_arn: str
    role: RoleSpec

    @property
    def account(self) -> str:
        return self.assumed_arn.split(":")[4]

    def fresh(self, now: float) -> bool:
        return self.expires_at - _REFRESH_MARGIN > now


def roles_from_extra(extra: dict[str, Any]) -> dict[str, RoleSpec]:
    """Parse ``[tool_extras."aws.roles"]``; loud on a malformed entry."""
    raw = extra.get(EXTRAS_KEY)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise AwsError(f'[tool_extras."{EXTRAS_KEY}"] must be a table of accounts')
    roles: dict[str, RoleSpec] = {}
    for name, body in raw.items():
        if not isinstance(body, dict) or not isinstance(body.get("role_arn"), str):
            raise AwsError(f'aws.roles.{name} needs a role_arn string')
        arn = body["role_arn"].strip()
        if not _ROLE_ARN.match(arn):
            raise AwsError(f"aws.roles.{name}: {arn!r} is not an IAM role ARN")
        audience = str(body.get("audience") or DEFAULT_AUDIENCE).strip()
        roles[str(name)] = RoleSpec(integration=str(name), role_arn=arn, audience=audience)
    return roles


def session_name(prefix: str, agent: str) -> str:
    return _SESSION_NAME_BAD.sub("-", f"{prefix}{agent}")[:64].ljust(2, "x")


def check_read_only(service: str, action: str) -> str | None:
    """Why this action may not go through, or None."""
    if not action or not action[0].isupper():
        return "action is the API operation name as AWS spells it, e.g. DescribeInstances"
    if not action.startswith(READ_VERBS):
        return f"{action} is not a read; this lane forwards only {', '.join(READ_VERBS[:6])}… actions"
    if (service, action) in DATA_READS:
        return f"{service}:{action} returns data, not configuration, and is refused on this lane"
    return None


# ---- identity: the gateway's own Google ID token ------------------------------


async def web_identity_token(audience: str) -> str:
    path = os.environ.get(TOKEN_FILE_ENV, "").strip()
    if path:
        return (await anyio.Path(path).read_text()).strip()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
            resp = await client.get(
                METADATA_IDENTITY_URL,
                params={"audience": audience, "format": "full"},
                headers={"Metadata-Flavor": "Google"},
            )
    except httpx.HTTPError as exc:
        raise AwsError(f"no identity token: the metadata server did not answer ({exc})") from exc
    if resp.status_code != 200:
        raise AwsError(
            f"no identity token: the metadata server answered {resp.status_code}; the gateway's "
            "Kubernetes service account needs a Google service account linked to it"
        )
    return resp.text.strip()


def identity_from_token(token: str) -> dict[str, str]:
    """The claims an account owner needs for the role's trust policy. Our own
    token, read without verifying: it is shown, not trusted."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError) as exc:
        raise AwsError("the identity token is not a JWT") from exc
    return {
        "issuer": str(claims.get("iss", "")),
        "subject": str(claims.get("sub", "")),
        "email": str(claims.get("email", "")),
        "audience": str(claims.get("aud", "")),
    }


# ---- STS + the read itself (botocore, in a thread) ----------------------------


def _assume_sync(role: RoleSpec, token: str, name: str) -> AwsSession:
    try:
        import botocore.session
        from botocore import UNSIGNED
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError as exc:  # pragma: no cover - the [aws] extra is missing
        raise AwsError("botocore is not installed; install liminal with the [aws] extra") from exc
    sts = botocore.session.get_session().create_client(
        "sts", region_name=DEFAULT_REGION, config=Config(signature_version=UNSIGNED)
    )
    try:
        resp = sts.assume_role_with_web_identity(
            RoleArn=role.role_arn,
            RoleSessionName=name,
            WebIdentityToken=token,
            DurationSeconds=SESSION_SECONDS,
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AwsError(
            f"AWS refused the role {role.role_arn}: {err.get('Code', 'error')} "
            f"{err.get('Message', '')}".strip()
        ) from exc
    except BotoCoreError as exc:
        raise AwsError(f"the STS call failed before it left the gateway: {exc}") from exc
    creds = resp["Credentials"]
    return AwsSession(
        access_key=creds["AccessKeyId"],
        secret_key=creds["SecretAccessKey"],
        token=creds["SessionToken"],
        expires_at=creds["Expiration"].timestamp(),
        assumed_arn=resp["AssumedRoleUser"]["Arn"],
        role=role,
    )


def _invoke_sync(session: AwsSession, service: str, action: str, params: dict, region: str) -> Any:
    import botocore.session
    from botocore import xform_name
    from botocore.exceptions import BotoCoreError, ClientError, UnknownServiceError

    try:
        client = botocore.session.get_session().create_client(
            service,
            region_name=region,
            aws_access_key_id=session.access_key,
            aws_secret_access_key=session.secret_key,
            aws_session_token=session.token,
        )
    except UnknownServiceError as exc:
        raise AwsError(f"{service!r} is not an AWS service name (use the CLI spelling, e.g. ec2, iam, s3)") from exc
    if action not in client.meta.service_model.operation_names:
        raise AwsError(f"{service} has no action {action}")
    try:
        return getattr(client, xform_name(action))(**params)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AwsError(f"{service}:{action} failed: {err.get('Code', 'error')} {err.get('Message', '')}".strip()) from exc
    except (BotoCoreError, TypeError) as exc:
        raise AwsError(f"{service}:{action} failed: {exc}") from exc


async def assume_role(role: RoleSpec, token: str, name: str) -> AwsSession:
    return await anyio.to_thread.run_sync(_assume_sync, role, token, name)


async def invoke(session: AwsSession, service: str, action: str, params: dict, region: str) -> Any:
    return await anyio.to_thread.run_sync(_invoke_sync, session, service, action, params, region)


async def probe(role_arn: str, audience: str = DEFAULT_AUDIENCE, *, who: str = "kobo-room") -> dict[str, str]:
    """Assume the role once as the room, for the set-up page's check."""
    if not _ROLE_ARN.match(role_arn):
        raise AwsError(f"{role_arn!r} is not an IAM role ARN")
    role = RoleSpec(integration="probe", role_arn=role_arn, audience=audience or DEFAULT_AUDIENCE)
    token = await web_identity_token(role.audience)
    session = await assume_role(role, token, session_name("probe-", who))
    return {"account": session.account, "arn": session.assumed_arn, "role_arn": role_arn}


# ---- the handler --------------------------------------------------------------


@dataclass
class AwsHandler:
    token_source: Callable[[str], Awaitable[str]] = web_identity_token
    assume: Callable[..., Awaitable[AwsSession]] = assume_role
    invoke: Callable[..., Awaitable[Any]] = invoke
    now: Callable[[], float] = time.time
    _sessions: dict[tuple[str, str], AwsSession] = field(default_factory=dict, init=False)

    def tools(self) -> list[ToolSpec]:
        account = {
            "type": "string",
            "description": "Which connected account, when the agent reaches more than one.",
        }
        return [
            ToolSpec(
                name="whoami",
                description="Which AWS account and role this agent reaches.",
                input_schema={"type": "object", "properties": {"account": account}},
            ),
            ToolSpec(
                name="call",
                description=(
                    "Run one read-only AWS API action (Describe*, List*, Get*, ...) and return "
                    "its response as JSON."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "service": {"type": "string", "description": "CLI spelling: ec2, iam, s3, cloudtrail, ce"},
                        "action": {"type": "string", "description": "API spelling: DescribeInstances, ListBuckets"},
                        "params": {"type": "object", "description": "The action's request parameters."},
                        "region": {"type": "string", "description": f"Default {DEFAULT_REGION}."},
                        "account": account,
                    },
                    "required": ["service", "action"],
                },
            ),
        ]

    def capability_card(self) -> dict[str, Any]:
        return CARD

    def _permitted(self, ctx: Context, roles: dict[str, RoleSpec]) -> dict[str, RoleSpec]:
        if not ctx.granted_scopes or "admin:*" in ctx.granted_scopes:
            return roles
        return {n: r for n, r in roles.items() if f"{n}:read" in ctx.granted_scopes}

    async def _session(self, ctx: Context, payload: dict[str, Any]) -> AwsSession:
        roles = roles_from_extra(ctx.extra)
        if not roles:
            raise AwsError(
                'no AWS account is connected to this gateway: the trust registry has no '
                f'[tool_extras."{EXTRAS_KEY}"] table'
            )
        permitted = self._permitted(ctx, roles)
        wanted = payload.get("account")
        if wanted is not None and not isinstance(wanted, str):
            raise AwsError("'account' must be a string")
        if wanted:
            if wanted not in roles:
                raise AwsError(f"no connected account {wanted!r}; connected: {', '.join(sorted(roles))}")
            if wanted not in permitted:
                raise AwsError(f"this agent has no lane to {wanted!r}")
            role = roles[wanted]
        elif len(permitted) == 1:
            role = next(iter(permitted.values()))
        elif not permitted:
            raise AwsError("this agent has no lane to any connected AWS account")
        else:
            raise AwsError(f"say which account: {', '.join(sorted(permitted))}")
        key = (role.integration, ctx.agent_name)
        cached = self._sessions.get(key)
        if cached is not None and cached.role == role and cached.fresh(self.now()):
            return cached
        token = await self.token_source(role.audience)
        session = await self.assume(role, token, session_name("kobo-", ctx.agent_name))
        self._sessions[key] = session
        log.info("aws.assumed", account=session.account, agent=ctx.agent_name, role=role.role_arn)
        return session

    async def dispatch(self, name: str, payload: dict[str, Any], ctx: Context) -> ToolResult:
        try:
            if name == "whoami":
                s = await self._session(ctx, payload)
                return ToolResult.text(json.dumps({
                    "account": s.account, "role_arn": s.role.role_arn, "integration": s.role.integration,
                    "assumed_arn": s.assumed_arn, "expires_in_seconds": int(s.expires_at - self.now()),
                }))
            if name == "call":
                service = str(payload.get("service", "")).strip().lower()
                action = str(payload.get("action", "")).strip()
                params = payload.get("params") or {}
                region = str(payload.get("region") or DEFAULT_REGION).strip()
                if not service:
                    return ToolResult.failure("'service' is required")
                if not isinstance(params, dict):
                    return ToolResult.failure("'params' must be an object")
                refusal = check_read_only(service, action)
                if refusal is not None:
                    return ToolResult.failure(refusal)
                s = await self._session(ctx, payload)
                result = await self.invoke(s, service, action, params, region)
                if isinstance(result, dict):
                    result.pop("ResponseMetadata", None)
                text = json.dumps(result, default=str)
                if len(text) > _MAX_RESULT_CHARS:
                    text = text[:_MAX_RESULT_CHARS] + f'... [truncated at {_MAX_RESULT_CHARS} characters; narrow the request]'
                return ToolResult.text(text)
            return ToolResult.failure(f"unknown tool {name!r}")
        except AwsError as exc:
            return ToolResult.failure(str(exc))


_SINGLETON: AwsHandler | None = None


def get_handler() -> Handler:
    """Entry-point factory."""
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = AwsHandler()
    return _SINGLETON
