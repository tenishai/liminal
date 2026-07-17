"""Unit tests for the fail-closed secret guard (limenal#50)."""

from __future__ import annotations

import pytest

from limenal.server.secret_guard import scan_for_secrets, scan_tool_call


# ---- real secret shapes are caught ----------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIE...", ["pem_private_key"]),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", ["pem_private_key"]),
        ("token ghp_" + "A" * 36, ["github_token"]),
        ("AKIAIOSFODNN7EXAMPLE", ["aws_access_key_id"]),
        ("xoxb-123456789012-abcdefABCDEF", ["slack_token"]),
        # sk- keys must contain a digit in the tail (limenal#52); real keys do.
        ("key sk-" + "a" * 20 + "0042", ["sk_api_key"]),
        # hyphenated modern keys (OpenAI project / Anthropic) — must not split
        ("naked sk-ant-api03-" + "a" * 24, ["sk_api_key"]),
        ("sk-proj-" + "a" * 20 + "1234", ["sk_api_key"]),
        ("ghr_" + "D" * 36, ["github_token"]),  # refresh token
        ("api_key = 9f8s7d6f5g4h3j2k1l0z", ["assigned_secret"]),
        ('password: "hunter2hunter2hunter2"', ["assigned_secret"]),
    ],
)
def test_real_secret_shapes_are_flagged(text, expected) -> None:
    assert scan_for_secrets(text) == expected


def test_multiple_distinct_hits_deduped_and_sorted() -> None:
    text = "AKIAIOSFODNN7EXAMPLE and ghp_" + "B" * 36
    assert scan_for_secrets(text) == ["aws_access_key_id", "github_token"]


def test_kebab_case_slug_is_not_a_false_positive() -> None:
    # limenal#52: a long digit-free kebab-case slug (e.g. a CSS class name in a
    # files.write payload) must not trip the sk- guard as a fail-closed false
    # positive. Real sk- keys always carry a digit; a prose/slug collision won't.
    assert scan_for_secrets("class sk-skeleton-loader-component-wrapper-xl") == []


# ---- placeholders and clean text are NOT flagged --------------------------


@pytest.mark.parametrize(
    "text",
    [
        "",
        "just ordinary prose mentioning tokens and secrets in the abstract",
        "api_key = ${OPENAI_API_KEY}",
        "api_key = $OPENAI_API_KEY",
        "secret: REDACTED",
        "token = <YOUR_TOKEN_HERE>",
        "password = changeme",
        "api_key = your-token-here",
        "access_key = example-key",
        "api_key = xxxxxxxxxxxx",
    ],
)
def test_placeholders_and_clean_text_pass(text) -> None:
    assert scan_for_secrets(text) == []


# ---- scan_tool_call: only guarded tools + their content fields ------------


def test_guarded_tool_with_secret_is_flagged() -> None:
    assert scan_tool_call("memory.commit", {"content": "AKIAIOSFODNN7EXAMPLE"}) == [
        "aws_access_key_id"
    ]


def test_guarded_tool_with_placeholder_is_clean() -> None:
    assert scan_tool_call(
        "files.write", {"path": "/x", "content": "api_key = ${VAR}"}
    ) == []


def test_notify_send_scans_the_message_field() -> None:
    assert scan_tool_call("notify.send", {"message": "ghp_" + "C" * 36}) == [
        "github_token"
    ]


def test_notify_send_also_scans_the_title_sink() -> None:
    # title rides the outbound webhook body alongside message — guard it too
    assert scan_tool_call(
        "notify.send", {"title": "AKIAIOSFODNN7EXAMPLE", "message": "hi"}
    ) == ["aws_access_key_id"]


def test_unguarded_tool_is_never_scanned() -> None:
    # scratchpad is not a persist-to-corpus/file/notify sink, so it isn't guarded
    assert scan_tool_call(
        "scratchpad.set", {"key": "k", "value": "AKIAIOSFODNN7EXAMPLE"}
    ) == []


def test_non_dict_or_missing_arguments_are_clean() -> None:
    assert scan_tool_call("memory.commit", None) == []
    assert scan_tool_call("memory.commit", "AKIAIOSFODNN7EXAMPLE") == []
    assert scan_tool_call("memory.commit", {"tags": "x"}) == []
