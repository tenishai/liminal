"""aws handler: read-only wall, lane-scoped accounts, cached sessions, identity claims."""
from __future__ import annotations

import base64
import json

import pytest

from liminal.handlers.aws import (
    AwsError,
    AwsHandler,
    AwsSession,
    RoleSpec,
    check_read_only,
    identity_from_token,
    roles_from_extra,
    session_name,
)
from liminal.protocol import Context

ROLE = "arn:aws:iam::123456789012:role/KoboAccess-Role"
PROD = "arn:aws:iam::210987654321:role/KoboAccess-Role"
EXTRA = {"aws.roles": {"aws": {"role_arn": ROLE}, "aws-prod": {"role_arn": PROD, "audience": "kobo"}}}


def _ctx(extra=EXTRA, scopes=()) -> Context:
    return Context(identity="sherlock", agent_name="sherlock-primus", credentials={}, extra=extra,
                   granted_scopes=frozenset(scopes))


def _handler(clock: list[float] | None = None):
    calls: list[tuple] = []
    clock = clock or [1000.0]

    async def token(aud: str) -> str:
        return f"token-for-{aud}"

    async def assume(role: RoleSpec, token: str, name: str, source: str) -> AwsSession:
        calls.append(("assume", role.integration, token, name, source))
        return AwsSession("AK", "SK", "ST", clock[0] + 3600, f"arn:aws:sts::{role.account}:assumed-role/KoboAccess-Role/{name}", role)

    async def invoke(session: AwsSession, service: str, action: str, params: dict, region: str):
        calls.append(("invoke", session.account, service, action, params, region))
        return {"Reservations": [], "ResponseMetadata": {"RequestId": "x"}}

    h = AwsHandler(token_source=token, assume=assume, invoke=invoke, now=lambda: clock[0])
    return h, calls


def test_roles_parse_and_a_bad_arn_is_loud():
    roles = roles_from_extra(EXTRA)
    assert roles["aws"].account == "123456789012" and roles["aws"].audience == "sts.amazonaws.com"
    assert roles["aws-prod"].audience == "kobo"
    assert roles_from_extra({}) == {}
    with pytest.raises(AwsError, match="not an IAM role ARN"):
        roles_from_extra({"aws.roles": {"x": {"role_arn": "arn:aws:iam::123:user/bob"}}})


def test_only_reads_go_through_and_data_reads_are_named():
    assert check_read_only("ec2", "DescribeInstances") is None
    assert "not a read" in check_read_only("s3", "DeleteBucket")
    assert "returns data" in check_read_only("s3", "GetObject")
    assert "returns data" in check_read_only("secretsmanager", "GetSecretValue")
    assert "as AWS spells it" in check_read_only("ec2", "describe_instances")


@pytest.mark.asyncio
async def test_a_write_is_refused_before_any_role_is_assumed():
    h, calls = _handler()
    r = await h.dispatch("call", {"service": "ec2", "action": "TerminateInstances"}, _ctx(scopes={"aws:read"}))
    assert r.is_error and "not a read" in r.error and calls == []


@pytest.mark.asyncio
async def test_the_lane_picks_the_account_and_the_session_is_tagged_and_cached():
    clock = [1000.0]
    h, calls = _handler(clock)
    ctx = _ctx(scopes={"aws:read"})  # a lane to "aws" only
    who = await h.dispatch("whoami", {}, ctx)
    assert json.loads(who.content[0]["text"])["account"] == "123456789012"
    call = await h.dispatch("call", {"service": "ec2", "action": "DescribeInstances", "region": "us-west-2"}, ctx)
    body = json.loads(call.content[0]["text"])
    assert body == {"Reservations": []}
    assumes = [c for c in calls if c[0] == "assume"]
    assert len(assumes) == 1, "two calls, one assume: the session is cached"
    _, integration, token, name, source = assumes[0]
    assert (integration, token, name, source) == ("aws", "token-for-sts.amazonaws.com", "kobo-sherlock-primus", "sherlock-primus")
    assert calls[-1] == ("invoke", "123456789012", "ec2", "DescribeInstances", {}, "us-west-2")
    # Near expiry the next call assumes again.
    clock[0] += 3400
    await h.dispatch("whoami", {}, ctx)
    assert len([c for c in calls if c[0] == "assume"]) == 2


@pytest.mark.asyncio
async def test_an_account_outside_the_lane_is_refused_and_two_lanes_must_name_one():
    h, _ = _handler()
    r = await h.dispatch("whoami", {"account": "aws-prod"}, _ctx(scopes={"aws:read"}))
    assert r.is_error and "no lane to 'aws-prod'" in r.error
    r = await h.dispatch("whoami", {}, _ctx(scopes={"aws:read", "aws-prod:read"}))
    assert r.is_error and "say which account" in r.error
    r = await h.dispatch("whoami", {"account": "aws-prod"}, _ctx(scopes={"aws:read", "aws-prod:read"}))
    assert json.loads(r.content[0]["text"])["account"] == "210987654321"
    r = await h.dispatch("whoami", {}, _ctx(extra={}, scopes={"aws:read"}))
    assert r.is_error and "no AWS account is connected" in r.error


def test_identity_claims_come_from_our_own_token_and_names_are_legal():
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": "https://accounts.google.com", "sub": "1234567890", "email": "liminal@p.iam.gserviceaccount.com", "aud": "sts.amazonaws.com",
    }).encode()).rstrip(b"=").decode()
    claims = identity_from_token(f"h.{payload}.s")
    assert claims == {"issuer": "https://accounts.google.com", "subject": "1234567890", "email": "liminal@p.iam.gserviceaccount.com", "audience": "sts.amazonaws.com"}
    with pytest.raises(AwsError):
        identity_from_token("nope")
    assert session_name("kobo-", "my agent:v2") == "kobo-my-agent-v2"
    assert len(session_name("kobo-", "a" * 100)) == 64
