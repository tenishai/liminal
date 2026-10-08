"""Every self-hosted CI job keeps the fork guard (#104).

Ported from tenishai/techne's tests/test_ci_workflow_triggers.py, where this
exists because a copied job twice inherited the self-hosted runner without the
guard. A new job copies `runs-on` from its neighbour and does not copy the
`if:`, and nothing fails when it doesn't. Now something does.

The guard is defence in depth only. For `pull_request` GitHub runs the PR's own
copy of test.yml, so a fork can delete it. The real controls are private
visibility and fork-PR workflows being off; see the comment in test.yml. This
test keeps honest copies honest.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "test.yml"

# The one allow-list, spelled once, in techne's form (techne#590). Compared
# EXACTLY rather than fuzzily ("does the `if` mention fork?"), because the
# realistic regression is not a missing guard but a subtly different one.
# Dropping the `github.event_name` clause reads correct and fails open.
TRUSTED_POOL = (
    "github.event_name == 'push' "
    "|| github.event_name == 'workflow_dispatch' "
    "|| (github.event_name == 'pull_request' "
    "&& github.event.pull_request.head.repo.full_name == github.repository)"
)
FORK_GUARD = "${{ " + TRUSTED_POOL + " }}"
# The literal negation of the same string, not a hand-written mirror, so an
# event nobody named gets a hosted run instead of an empty Checks tab.
FORK_ONLY = "${{ !(" + TRUSTED_POOL + ") }}"
# `integration` is manual dispatch only. That is narrower than the allow-list
# (workflow_dispatch is one of its three branches, and needs write access), so
# it is the one other exact `if:` a self-hosted job may carry. Widening it, for
# example with `|| github.ref == 'refs/heads/main'` once techne is public, must
# move it onto FORK_GUARD's shape and fails here until it does.
DISPATCH_ONLY = "github.event_name == 'workflow_dispatch'"
SELF_HOSTED_GUARDS = (FORK_GUARD, DISPATCH_ONLY)


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


# The standard GitHub-hosted runner labels, verbatim from GitHub's "GitHub-hosted
# runners" reference (read 2026-10-04). An exact set, not a pattern: a pattern
# such as `ubuntu-*` would also pass a custom label like `ubuntu-liminal-ci`.
# Anything not listed, including larger-runner labels, is treated as
# self-hosted and must carry the guard; add a label here when CI starts using it.
HOSTED_LABELS = frozenset(
    {
        "ubuntu-slim",
        "ubuntu-latest",
        "ubuntu-22.04",
        "ubuntu-24.04",
        "ubuntu-26.04",
        "ubuntu-22.04-arm",
        "ubuntu-24.04-arm",
        "ubuntu-26.04-arm",
        "windows-latest",
        "windows-2022",
        "windows-2025",
        "windows-2025-vs2026",
        "windows-11-arm",
        "windows-11-vs2026-arm",
        "macos-latest",
        "macos-14",
        "macos-15",
        "macos-26",
        "macos-15-intel",
        "macos-26-intel",
        "xcode-27",
    }
)


def _is_self_hosted(runs_on) -> bool:
    """True unless every label in `runs-on` is in HOSTED_LABELS, in any YAML
    spelling.

    Decided by allow-listing hosted labels, not by looking for `self-hosted`. A
    runner is addressed by any label it carries, so `runs-on: spark` or
    `runs-on: liminal-ci` reaches the self-hosted pool without the word appearing.
    An expression (`${{ vars.CI_RUNNER }}`) cannot be resolved here, a `group:`
    names a runner group, and an unreadable value is unknown, so all of those
    count as self-hosted and must carry the guard. Fail closed.
    """
    if isinstance(runs_on, dict):
        return bool(runs_on.get("group")) or _is_self_hosted(runs_on.get("labels"))
    if isinstance(runs_on, str):
        runs_on = [runs_on]
    if isinstance(runs_on, list) and runs_on:
        return not all(str(label) in HOSTED_LABELS for label in runs_on)
    return True


# Events only someone with write access can fire. A workflow triggered by
# nothing else cannot be started from a fork, so its self-hosted jobs are in the
# same trust pool as FORK_GUARD without a per-job `if:`. Deliberately narrow:
# `pull_request` (forks), `pull_request_target`, `workflow_run`, `issue_comment`
# and the rest are not here, and a workflow using any of them must guard each
# self-hosted job instead.
TRUSTED_TRIGGERS = frozenset({"push", "workflow_dispatch"})


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


def _unguarded_self_hosted_jobs(doc: dict) -> dict:
    """Self-hosted jobs that neither carry an exact guard nor sit in a workflow
    only trusted events can trigger (name -> its `if`)."""
    if _triggers(doc) <= TRUSTED_TRIGGERS:
        return {}
    jobs = doc.get("jobs") or {}
    return {
        name: job.get("if")
        for name, job in sorted(jobs.items())
        if _is_self_hosted(job.get("runs-on")) and job.get("if") not in SELF_HOSTED_GUARDS
    }


def test_every_workflow_guards_its_self_hosted_jobs():
    """Every workflow file, not only test.yml (`*.y*ml` because Actions reads
    both). This replaced a tripwire that failed on any second workflow: a new
    file is now checked rather than refused, so a workflow added by another
    tool (Gojira's, for one) passes when it is safe and fails when it is not.
    Like the rest of this file it keeps honest copies honest: a fork's pull
    request runs the fork's own workflow files (see the module docstring)."""
    workflows = sorted(WORKFLOW.parent.glob("*.y*ml"))
    assert WORKFLOW in workflows, (
        "test.yml is missing; this test would read nothing it was written for"
    )
    offenders = {}
    for path in workflows:
        bad = _unguarded_self_hosted_jobs(yaml.safe_load(path.read_text()))
        if bad:
            offenders[path.name] = bad
    assert not offenders, (
        "a self-hosted job can be started from a fork (#104).\n"
        f"offenders (workflow -> job -> its `if`): {offenders}\n"
        f"Either trigger the workflow only on {sorted(TRUSTED_TRIGGERS)}, or give each "
        f"self-hosted job the exact guard:\n  {FORK_GUARD}\n  or: {DISPATCH_ONLY}"
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
        ("spark", True),  # a bare custom label reaches the pool
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


SELF_HOSTED_JOB = {"runs-on": "${{ vars.CI_RUNNER || 'ubuntu-latest' }}"}


@pytest.mark.parametrize(
    ("on", "job", "unguarded"),
    [
        # push + dispatch only: safe without a per-job `if:` (gojira-ci.yaml's shape).
        ({"push": {"branches": ["main"]}, "workflow_dispatch": {}}, SELF_HOSTED_JOB, False),
        # A fork PR could start it, whatever spelling reaches the pool.
        (["push", "pull_request"], SELF_HOSTED_JOB, True),
        (["pull_request"], {"runs-on": "spark"}, True),
        (["pull_request"], {"runs-on": ["self-hosted", "liminal-ci"]}, True),
        (["pull_request"], {"runs-on": {"labels": ["spark"]}}, True),
        (["pull_request"], {"runs-on": {"group": "large"}}, True),
        (["pull_request"], {"runs-on": "ubuntu-liminal-ci"}, True),
        (["pull_request"], {"runs-on": []}, True),
        (["pull_request"], {}, True),  # no runs-on at all
        ("pull_request_target", SELF_HOSTED_JOB, True),
        ({"workflow_run": {"workflows": ["test"]}}, SELF_HOSTED_JOB, True),
        # The same exposure is fine once the job carries the exact guard.
        (["push", "pull_request"], {**SELF_HOSTED_JOB, "if": FORK_GUARD}, False),
        # A hosted job is out of scope whatever the triggers.
        (["pull_request"], {"runs-on": "ubuntu-latest"}, False),
        # An unreadable `on:` is never trusted.
        (None, SELF_HOSTED_JOB, True),
    ],
)
def test_the_rule_decides_each_shape(on, job, unguarded):
    doc = {True: on, "jobs": {"build": job}}
    assert bool(_unguarded_self_hosted_jobs(doc)) is unguarded


def test_every_self_hosted_job_carries_the_fork_guard():
    jobs = _jobs()
    self_hosted = {name for name, job in jobs.items() if _is_self_hosted(job.get("runs-on"))}
    # Without this, a classifier that never matches would pass every job.
    assert self_hosted, (
        "no self-hosted job found in test.yml. If CI left the self-hosted runner, "
        "retire this test deliberately rather than letting it pass on nothing."
    )

    offenders = {
        name: jobs[name].get("if")
        for name in sorted(self_hosted)
        if jobs[name].get("if") not in SELF_HOSTED_GUARDS
    }
    assert not offenders, (
        "every self-hosted job must carry the exact fork guard (#104).\n"
        f"expected: {FORK_GUARD}\n"
        f"      or: {DISPATCH_ONLY}\n"
        f"offending jobs (name -> its `if`): {offenders}\n"
        "A fork PR reaching the runner runs attacker code on the CI host."
    )


def test_fork_pr_is_the_literal_negation_on_a_hosted_runner():
    """The other half. Guarding the self-hosted jobs without a hosted path would
    leave a fork PR with an empty Checks tab, which reads like "nothing to
    report"."""
    fork_pr = _jobs()["fork-pr"]
    assert fork_pr.get("if") == FORK_ONLY, (
        f"fork-pr's `if:` must be the literal negation of the fork guard.\n"
        f"expected: {FORK_ONLY}\n"
        f"found:    {fork_pr.get('if')}"
    )
    assert not _is_self_hosted(fork_pr.get("runs-on")), (
        "fork-pr runs only for fork PRs; on the self-hosted pool it is the exposure, inverted"
    )


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
