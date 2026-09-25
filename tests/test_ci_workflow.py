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


def _is_self_hosted(runs_on) -> bool:
    """True when `runs-on` targets the self-hosted pool, in any YAML spelling.

    `runs-on` accepts a string, a list of labels, or a mapping with `labels:` /
    `group:`. Checking only the list form this file uses today would let the
    same exposure return through another spelling.

    An expression (`${{ matrix.os }}`, `${{ vars.RUNNER }}`) cannot be resolved
    here, so it counts as self-hosted: a job whose runner this test cannot see
    must carry the guard anyway. Fail closed.
    """
    if isinstance(runs_on, dict):
        return bool(runs_on.get("group")) or _is_self_hosted(runs_on.get("labels") or [])
    if isinstance(runs_on, str):
        runs_on = [runs_on]
    if isinstance(runs_on, list):
        return any("self-hosted" in str(label) or "${{" in str(label) for label in runs_on)
    return False


def test_test_yml_is_the_only_workflow():
    """This file checks one workflow. A second one would run jobs this test never
    reads, so its arrival has to be noticed. `*.y*ml` because Actions reads both
    .yml and .yaml."""
    workflows = sorted(p.name for p in WORKFLOW.parent.glob("*.y*ml"))
    assert workflows == ["test.yml"], (
        f"a second workflow appeared ({workflows}); extend this test to cover it "
        "before any of its jobs can reach the self-hosted runner"
    )


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
