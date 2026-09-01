"""Wire-format conversion — liminal#66 regression cover.

``ToolResult.failure`` puts the reason in ``.error`` and leaves ``.content``
empty. MCP has no ``error`` field on a tool result, so unless the message is
converted into content the agent receives a failure it cannot act on.
"""

from __future__ import annotations

from liminal.wire import to_spec_result_content


def test_failure_message_becomes_text_content() -> None:
    out = to_spec_result_content([], is_error=True, error="upstream 'jira' is down")
    assert out == [{"type": "text", "text": "upstream 'jira' is down"}]


def test_success_content_is_untouched() -> None:
    blocks = [{"type": "text", "text": "ok"}]
    assert to_spec_result_content(blocks, is_error=False, error=None) == blocks


def test_partial_content_is_preserved_alongside_the_error() -> None:
    out = to_spec_result_content(
        [{"type": "text", "text": "read 3 of 10 rows"}],
        is_error=True,
        error="timed out",
    )
    assert out == [
        {"type": "text", "text": "read 3 of 10 rows"},
        {"type": "text", "text": "timed out"},
    ]


def test_error_flag_without_a_message_adds_nothing() -> None:
    assert to_spec_result_content([], is_error=True, error=None) == []


def test_json_blocks_still_convert_to_spec_text() -> None:
    out = to_spec_result_content([{"type": "json", "data": {"a": 1}}])
    assert out == [{"type": "text", "text": '{"a": 1}'}]
