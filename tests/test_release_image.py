"""The release image: release.yml publishes ghcr.io/tenishai/liminal from a v* tag.

Ported from tenishai/cabal's tests/test_release_image.py with its release.yml, so the two
workflows keep the same guarantees: CI first, arm64 proved natively, only a matching
version tag publishes, and a published tag is never rebuilt.
"""
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
TEST = ROOT / ".github" / "workflows" / "test.yml"


def _on(doc: dict):
    return doc.get("on", doc.get(True))


def _version() -> str:
    m = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M)
    assert m, "pyproject.toml has no version line"
    return m.group(1)


def test_release_runs_on_version_tags_after_the_whole_ci():
    doc = yaml.safe_load(RELEASE.read_text())
    assert _on(doc)["push"] == {"tags": ["v*"]}
    assert doc["jobs"]["checks"]["uses"] == "./.github/workflows/test.yml"
    assert doc["jobs"]["release"]["needs"] == ["checks", "arm64"]
    assert doc["jobs"]["arm64"]["needs"] == "checks"
    assert "workflow_call" in _on(yaml.safe_load(TEST.read_text())), (
        "release.yml calls test.yml, which must accept workflow_call"
    )


def test_release_builds_with_the_techne_the_dockerfile_pins():
    text = RELEASE.read_text()
    assert "s/^ARG TECHNE_VERSION=//p' Dockerfile" in text
    steps = yaml.safe_load(text)["jobs"]["release"]["steps"]
    builds = [s for s in steps if str(s.get("uses", "")).startswith("docker/build-push-action@")]
    assert len(builds) == 2
    for s in builds:
        assert s["with"]["build-contexts"] == "techne=techne"
    published = builds[1]["with"]
    assert published["push"] is True
    assert "latest" not in published["tags"]



def test_arm64_is_built_and_run_on_a_native_runner_and_never_pushed():
    job = yaml.safe_load(RELEASE.read_text())["jobs"]["arm64"]
    assert job["runs-on"] == "ubuntu-24.04-arm"
    assert "if" not in job, "the arm64 job must run on dry runs too (issue #485)"
    assert job["permissions"] == {"contents": "read"}
    steps = {s.get("name", s.get("uses")): s for s in job["steps"]}
    assert not any("setup-qemu-action" in str(s.get("uses", "")) for s in job["steps"])
    build = steps["Build the arm64 image (never pushed)"]["with"]
    assert build["platforms"] == "linux/arm64"
    assert build["push"] is False and build["load"] is True
    assert build["build-contexts"] == "techne=techne"
    assert "cache-to" not in build
    # The arm64 image is built from the same inputs as the release's own build, so a pass
    # here says something about the image that gets published. Whole dicts, minus the keys
    # meant to differ, so a key added to one side only (a `target`, a `file`) fails too.
    release = _steps()["Build the image for this machine"]["with"]
    differ = {"platforms", "push", "load", "tags"}

    def strip(w: dict) -> dict:
        return {k: v for k, v in w.items() if k not in differ}

    assert strip(build) == strip(release)
    # The techne directory those builds read is checked out the same way in both jobs.
    techne = "Checkout techne at the tag the Dockerfile pins"
    assert steps[techne]["with"] == _steps()[techne]["with"]


def test_both_jobs_read_the_same_version_and_techne_tag(checkout):
    """The `version` outputs feed the techne checkout and the image check, so the arm64
    job's own version step must agree with the release job's on the same checkout."""
    job = yaml.safe_load(RELEASE.read_text())["jobs"]["arm64"]
    arm = next(s for s in job["steps"] if s.get("id") == "version")
    _, arm_out = _run(arm["run"], {}, checkout)
    _, rel_out = _run(_steps()[VERSION_STEP]["run"],
                      {"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"}, checkout)
    assert arm_out["techne"] == rel_out["techne"] == "v0.20.0"
    assert arm_out["version"] == rel_out["version"] == "1.2.3"
    assert arm_out["day"] == rel_out["day"]


def _steps() -> dict:
    steps = yaml.safe_load(RELEASE.read_text())["jobs"]["release"]["steps"]
    return {s.get("name", s.get("uses")): s for s in steps}


VERSION_STEP = "The tag names the version the project declares (a branch is a dry run)"
CHECK_STEP = "Is this tag's image already published"


def _run(script: str, env: dict, cwd: Path) -> tuple[int, dict]:
    """Run a step's script as Actions would (bash -e, or the step's own `set`), with
    $GITHUB_OUTPUT in cwd, and return the exit code and the outputs it wrote."""
    out = cwd / "github_output"
    out.write_text("")
    path = f"{cwd / 'bin'}:/usr/bin:/bin"
    proc = subprocess.run(
        ["bash", "-e", "-c", script], cwd=cwd, capture_output=True, text=True,
        env={"PATH": path, "GITHUB_OUTPUT": str(out), **env},
    )
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
    return proc.returncode, outputs


@pytest.fixture
def checkout(tmp_path):
    """A liminal/ checkout as the version step sees it: pyproject, Dockerfile, a commit."""
    repo = tmp_path / "liminal"
    repo.mkdir()
    (repo / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "1.2.3"\n')
    (repo / "Dockerfile").write_text("ARG TECHNE_VERSION=0.20.0\n")
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "x"], check=True)
    return repo


@pytest.mark.parametrize(
    ("ref_type", "ref_name", "rc", "publish", "check_tag"),
    [
        ("tag", "v1.2.3", 0, "true", "v1.2.3"),
        ("branch", "main", 0, "false", "v1.2.3"),
        ("tag", "v1.2.4", 1, None, None),  # the tag disagrees with pyproject.toml
        ("tag", "nightly", 1, None, None),  # not a version tag
    ],
)
def test_only_a_matching_version_tag_publishes(checkout, ref_type, ref_name, rc, publish, check_tag):
    script = _steps()[VERSION_STEP]["run"]
    code, out = _run(script, {"GITHUB_REF_TYPE": ref_type, "GITHUB_REF_NAME": ref_name}, checkout)
    assert code == rc
    assert out.get("publish") == publish
    assert out.get("check_tag") == check_tag


FAKE_DOCKER = """#!/bin/bash
# `docker buildx imagetools inspect REF --format ...`, answered from $FAKE_*.
printf '%s' "$FAKE_STDOUT"
printf '%s' "$FAKE_STDERR" >&2
exit "$FAKE_RC"
"""


@pytest.mark.parametrize(
    ("stdout", "stderr", "rc", "publish", "exit_code", "reuse", "subject"),
    [
        # Published, on a tag: reuse it, check and scan the published digest.
        ('"sha256:ab12"\n', "", 0, "true", 0, "true", "ghcr.io/tenishai/liminal@sha256:ab12"),
        # Published, on a dry run: never reuse; the dry run checks its own build.
        ('"sha256:ab12"', "", 0, "false", 0, "false", "candidate:release"),
        # Not published yet: build it.
        ("", "ERROR: ghcr.io/tenishai/liminal:v1.2.3: not found\n", 1, "true", 0, "false", "candidate:release"),
        # Anything else fails the run, so a registry error can't pass for "missing".
        ("", "ERROR: failed to authorize: 403 Forbidden\n", 1, "true", 1, None, None),
        ("", "ERROR: 502 Bad Gateway\n", 1, "true", 1, None, None),
        ("noise", "", 1, "true", 1, None, None),
        ("", "", 0, "true", 1, None, None),  # succeeded but printed no digest
    ],
)
def test_the_existence_check_reuses_only_a_published_tag(
    tmp_path, stdout, stderr, rc, publish, exit_code, reuse, subject
):
    (tmp_path / "bin").mkdir()
    fake = tmp_path / "bin" / "docker"
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)
    step = _steps()[CHECK_STEP]
    assert step["shell"] == "bash"
    env = {
        "REF": "ghcr.io/tenishai/liminal:v1.2.3", "PUBLISH": publish,
        "FAKE_STDOUT": stdout, "FAKE_STDERR": stderr, "FAKE_RC": str(rc),
    }
    code, out = _run(step["run"], env, tmp_path)
    assert code == exit_code
    assert out.get("reuse") == reuse
    assert out.get("subject") == subject


def test_a_reused_image_is_never_rebuilt_or_pushed_and_its_digest_is_released():
    steps = _steps()
    # Equality, not substrings: `a && b` and `a || b` share both terms, and `||` would push
    # from a branch.
    assert steps["Build the image for this machine"]["if"] == "steps.published.outputs.reuse != 'true'"
    assert steps["Build and publish, both architectures"]["if"] == (
        "steps.version.outputs.publish == 'true' && steps.published.outputs.reuse != 'true'"
    )
    assert steps["The GitHub release"]["if"] == "steps.version.outputs.publish == 'true'"
    for name in ("No high or critical vulnerability that has a fix", "SBOM"):
        assert steps[name]["with"]["image"] == "${{ steps.published.outputs.subject }}", name
    assert steps["The image starts and reports the tagged version"]["env"]["SUBJECT"] == (
        "${{ steps.published.outputs.subject }}"
    )
    assert steps["No high or critical vulnerability that has a fix"]["with"]["fail-build"] == (
        "${{ steps.published.outputs.reuse != 'true' }}"
    )
    assert steps["The GitHub release"]["env"]["DIGEST"] == (
        "${{ steps.published.outputs.reuse == 'true' && steps.published.outputs.digest"
        " || steps.build.outputs.digest }}"
    )


def test_the_scan_reads_the_repo_ignore_list_and_each_entry_names_a_version():
    scan = _steps()["No high or critical vulnerability that has a fix"]["with"]
    assert scan["config"] == "liminal/.grype.yaml"
    # Empty until a finding needs one; each entry must still name a package version.
    ignores = yaml.safe_load((ROOT / ".grype.yaml").read_text())["ignore"]
    assert isinstance(ignores, list)
    for entry in ignores:
        assert entry["package"]["name"] and entry["package"]["version"], entry


ARM_CHECK = "The arm64 image runs natively and reports the version"
FAKE_ARM_DOCKER = """#!/bin/bash
# `docker run --rm IMAGE CMD...`: answer uname, the version probe and the CLI from $FAKE_*.
echo "$*" >> calls
case "$*" in
  *"uname -m") echo "$FAKE_ARCH";;
  *liminal.__version__*) echo "$FAKE_VERSION";;
  *"liminal --help") exit "$FAKE_CLI_RC";;
esac
"""


@pytest.mark.parametrize(
    ("arch", "version", "cli_rc", "passes"),
    [
        ("aarch64", "1.2.3", 0, True),
        ("x86_64", "1.2.3", 0, False),  # emulated or wrong-arch image: not proof of arm64
        ("aarch64", "1.2.2", 0, False),  # the image is not this checkout's version
        ("aarch64", "1.2.3", 2, False),  # the CLI does not start
    ],
)
def test_the_arm64_check_needs_aarch64_the_version_and_a_working_cli(
    tmp_path, arch, version, cli_rc, passes
):
    job = yaml.safe_load(RELEASE.read_text())["jobs"]["arm64"]
    script = next(s for s in job["steps"] if s.get("name") == ARM_CHECK)["run"]
    (tmp_path / "bin").mkdir()
    fake = tmp_path / "bin" / "docker"
    fake.write_text(FAKE_ARM_DOCKER)
    fake.chmod(0o755)
    env = {"VERSION": "1.2.3", "FAKE_ARCH": arch, "FAKE_VERSION": version, "FAKE_CLI_RC": str(cli_rc)}
    code, _ = _run(script, env, tmp_path)
    assert (code == 0) is passes
    if passes:
        assert all("candidate:arm64" in line for line in (tmp_path / "calls").read_text().splitlines())
