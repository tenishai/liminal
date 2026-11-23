"""CI runs on GitHub-hosted runners only, and `ci` is a gate a skip cannot pass (#104).

Ported from tenishai/techne's tests/test_ci_workflow_triggers.py. The repo is
public, so three rules hold and this file pins each:

1. No job in any workflow targets a self-hosted runner. A self-hosted runner
   reachable from a public repo would run a stranger's pull request.
2. `unit` has no `if:`, so it runs for every pull request, forks included. A
   fork PR runs the real tests rather than a guarded twin.
3. A `ci` job, which a branch ruleset requires by name together with `dco`,
   fails unless `unit` succeeded. GitHub counts a skipped job as passing, so
   `ci` runs with `if: always()` and checks the result itself.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "test.yml"


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


# The standard GitHub-hosted runner labels, verbatim from GitHub's "GitHub-hosted
# runners" reference (read 2026-10-04). An exact set, not a pattern: a pattern
# such as `ubuntu-*` would also pass a custom label like `ubuntu-liminal-ci`.
# Anything not listed, including larger-runner labels, is treated as
# self-hosted; add a label here when CI starts using it.
HOSTED_LABELS = frozenset(
    {
        "ubuntu-slim", "ubuntu-latest", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04",
        "ubuntu-22.04-arm", "ubuntu-24.04-arm", "ubuntu-26.04-arm",
        "windows-latest", "windows-2022", "windows-2025", "windows-2025-vs2026",
        "windows-11-arm", "windows-11-vs2026-arm",
        "macos-latest", "macos-14", "macos-15", "macos-26",
        "macos-15-intel", "macos-26-intel", "xcode-27",
    }
)


def _is_self_hosted(runs_on) -> bool:
    """True unless every label in `runs-on` is in HOSTED_LABELS, in any YAML
    spelling.

    Decided by allow-listing hosted labels, not by looking for `self-hosted`. A
    runner is addressed by any label it carries, so `runs-on: spark` or
    `runs-on: liminal-ci` reaches a self-hosted runner without the word appearing.
    An expression (`${{ vars.CI_RUNNER }}`) cannot be resolved here, a `group:`
    names a runner group, and an unreadable value is unknown, so all of those
    count as self-hosted. Fail closed.
    """
    if isinstance(runs_on, dict):
        return bool(runs_on.get("group")) or _is_self_hosted(runs_on.get("labels"))
    if isinstance(runs_on, str):
        runs_on = [runs_on]
    if isinstance(runs_on, list) and runs_on:
        return not all(str(label) in HOSTED_LABELS for label in runs_on)
    return True


# Events only someone with write access can fire. A workflow triggered by
# nothing else cannot be started from a fork. Deliberately narrow:
# `pull_request` (forks), `pull_request_target`, `workflow_run`, `issue_comment`
# and the rest are not here.
TRUSTED_TRIGGERS = frozenset({"push", "workflow_dispatch"})

# The expression Gojira's generated deploy workflow used. No workflow here may
# carry it any more: the generated file is gone, and an unresolvable runs-on
# fails closed like any other.
GOJIRA_RUNS_ON = "${{ vars.CI_RUNNER || 'ubuntu-latest' }}"


def _triggers(doc: dict) -> set[str]:
    """The event names a workflow's `on:` names, in any YAML spelling.

    PyYAML reads the bare key `on` as the boolean True (YAML 1.1), so look for
    both. `on:` may be a string, a list of names, or a mapping keyed by name.
    An unreadable shape returns a sentinel that is never trusted. Fail closed.
    """
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(e) for e in on}
    if isinstance(on, dict):
        return {str(e) for e in on}
    return {"<unreadable on:>"}


def _self_hosted_jobs(doc: dict) -> dict:
    """Jobs that target a self-hosted runner (name -> its `runs-on`). There is
    no exception: any trigger, any spelling, an unresolvable expression included."""
    jobs = doc.get("jobs") or {}
    return {
        name: job.get("runs-on")
        for name, job in sorted(jobs.items())
        if _is_self_hosted(job.get("runs-on"))
    }


def test_no_workflow_targets_a_self_hosted_runner():
    """Every workflow file, not only test.yml (`*.y*ml` because Actions reads
    both), so a workflow added by another tool passes when it is safe and fails
    when it is not."""
    workflows = sorted(WORKFLOW.parent.glob("*.y*ml"))
    assert WORKFLOW in workflows, "test.yml is missing; this test would read nothing it was written for"
    offenders = {}
    for path in workflows:
        bad = _self_hosted_jobs(yaml.safe_load(path.read_text()))
        if bad:
            offenders[path.name] = bad
    assert not offenders, (
        "this repo is public: no job may run on a self-hosted runner, because a fork's "
        "pull request would run its code there.\n"
        f"offenders (workflow -> job -> its `runs-on`): {offenders}\n"
        "Use a GitHub-hosted label from HOSTED_LABELS."
    )


@pytest.mark.parametrize(
    ("on", "expected"),
    [
        ("push", {"push"}),
        (["push", "workflow_dispatch"], {"push", "workflow_dispatch"}),
        ({"push": {"branches": ["main"]}, "workflow_dispatch": {}}, {"push", "workflow_dispatch"}),
        (None, {"<unreadable on:>"}),
    ],
)
def test_triggers_reads_every_spelling(on, expected):
    assert _triggers({True: on}) == expected
    assert _triggers({"on": on}) == expected


@pytest.mark.parametrize(
    ("runs_on", "self_hosted"),
    [
        ("ubuntu-latest", False),
        (["ubuntu-24.04-arm"], False),
        ("macos-15", False),
        ("spark", True),  # a bare custom label reaches a runner
        ("liminal-ci", True),
        ("ubuntu-liminal-ci", True),  # a hosted-looking prefix is not enough
        ("windows-spark", True),
        (["self-hosted", "linux", "x64", "liminal-ci"], True),
        (["ubuntu-latest", "spark"], True),  # every label must be hosted
        ("${{ vars.CI_RUNNER || 'ubuntu-latest' }}", True),
        ({"group": "large"}, True),
        ({"labels": ["ubuntu-latest"]}, False),
        ({"labels": ["spark"]}, True),
        (None, True),
        ([], True),
    ],
)
def test_is_self_hosted_allow_lists_hosted_images(runs_on, self_hosted):
    assert _is_self_hosted(runs_on) is self_hosted


@pytest.mark.parametrize(
    ("on", "runs_on", "flagged"),
    [
        # Every spelling that reaches a self-hosted runner is flagged on a PR workflow.
        (["pull_request"], "spark", True),
        (["pull_request"], ["self-hosted", "linux", "x64", "liminal-ci"], True),
        (["pull_request"], {"labels": ["spark"]}, True),
        (["pull_request"], {"group": "large"}, True),
        (["pull_request"], "ubuntu-liminal-ci", True),
        (["pull_request"], "${{ vars.CI_RUNNER }}", True),  # unresolvable: fail closed
        (["pull_request"], GOJIRA_RUNS_ON, True),
        (["pull_request"], [], True),
        (["pull_request"], None, True),  # no runs-on at all
        # Flagged on a push-only workflow too: trusted triggers do not excuse a pool.
        (["push"], "spark", True),
        (["push"], "${{ vars.CI_RUNNER }}", True),
        # Hosted is fine whatever the triggers.
        (["pull_request"], "ubuntu-latest", False),
        (["pull_request"], {"labels": ["ubuntu-24.04"]}, False),
        # Gojira's old expression is flagged even on a workflow a fork cannot trigger.
        ({"push": {"branches": ["main"]}, "workflow_dispatch": {}}, GOJIRA_RUNS_ON, True),
        # An unreadable `on:` is never trusted.
        (None, GOJIRA_RUNS_ON, True),
    ],
)
def test_the_rule_decides_each_shape(on, runs_on, flagged):
    job = {} if runs_on is None else {"runs-on": runs_on}
    doc = {True: on, "jobs": {"build": job}}
    assert bool(_self_hosted_jobs(doc)) is flagged


def test_unit_is_never_skipped_on_a_pull_request():
    """A fork PR must run the real tests. Any job-level `if:` on unit can skip
    it (and a skipped job reads as passing), so there must be none."""
    unit = _jobs().get("unit")
    assert unit is not None, "test.yml has no `unit` job"
    assert "if" not in unit, (
        f"unit has `if: {unit.get('if')}`; it must run on every pull_request, forks included"
    )
    assert "pull_request" in _triggers(yaml.safe_load(WORKFLOW.read_text())), (
        "test.yml must trigger on pull_request, or unit never runs for a PR"
    )


def _ci_step_exit_code(step: dict, unit_result: str) -> int:
    """Run the `ci` job's step in bash with `${{ needs.unit.result }}` set to
    `unit_result`, and return its exit code. The substitution is textual, in
    `run:` and in `env:` values, which covers how a step reads the expression."""
    expr = "${{ needs.unit.result }}"
    env = {k: str(v).replace(expr, unit_result) for k, v in (step.get("env") or {}).items()}
    script = step["run"].replace(expr, unit_result)
    return subprocess.run(["bash", "-e", "-c", script], env={"PATH": "/usr/bin:/bin", **env}).returncode


def test_ci_job_gates_on_unit_succeeding():
    ci = _jobs().get("ci")
    assert ci is not None, "test.yml has no `ci` job; a branch ruleset requires it by name"
    needs = ci.get("needs")
    needs = [needs] if isinstance(needs, str) else (needs or [])
    assert "unit" in needs, f"ci must need unit, found needs: {needs}"
    assert str(ci.get("if")).strip().removeprefix("${{").removesuffix("}}").strip() == "always()", (
        f"ci must run `if: always()` so it reports when unit fails, is cancelled or is skipped; found {ci.get('if')!r}"
    )
    assert not _is_self_hosted(ci.get("runs-on"))
    steps = ci.get("steps") or []
    assert len(steps) == 1 and "run" in steps[0], f"ci must be one `run` step, found {steps}"
    assert _ci_step_exit_code(steps[0], "success") == 0, "ci must pass when unit succeeded"
    for result in ("failure", "cancelled", "skipped", ""):
        assert _ci_step_exit_code(steps[0], result) != 0, f"ci must fail when unit's result is {result!r}"


def test_every_third_party_action_is_pinned_to_a_full_commit_sha():
    """A tag can be moved after review; a commit SHA cannot."""
    import re

    pinned = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
    unpinned = [
        step["uses"]
        for job in _jobs().values()
        for step in job.get("steps", [])
        if "uses" in step and not step["uses"].startswith("./") and not pinned.match(step["uses"])
    ]
    assert not unpinned, f"pin these to a full commit SHA with a `# vX.Y.Z` comment: {unpinned}"
