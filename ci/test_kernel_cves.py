"""Tests for the kernel CVE assessment"""

# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

import importlib.util
import json
import os
import subprocess
import sys

import pytest

SCRIPTS = os.path.join(os.path.dirname(__file__), os.pardir, "scripts")
SCRIPT = os.path.join(SCRIPTS, "kernel-cves.py")

spec = importlib.util.spec_from_file_location("kernel_cves", SCRIPT)
kernel_cves = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel_cves)

QLI_VERSION = "7.2.0+git20261008~gb8f0c6b1ab06-0qli1~bpo13+1"


def semver(introduced, *fixes, mainline=None):
    # the semver block of a vulns.git record: introduced in a version, fixed
    # in stable releases and in a mainline release
    versions = [{"version": introduced, "status": "affected"},
                {"version": "0", "lessThan": introduced,
                 "status": "unaffected", "versionType": "semver"}]
    for fix in fixes:
        branch = ".".join(fix.split(".")[:2])
        versions.append({"version": fix, "lessThanOrEqual": f"{branch}.*",
                         "status": "unaffected", "versionType": "semver"})
    if mainline:
        versions.append({"version": mainline, "lessThanOrEqual": "*",
                         "status": "unaffected",
                         "versionType": "original_commit_for_fix"})
    return versions


def record(cve_id, versions, files, default="affected", severity=None,
           fixes=()):
    cna = {
        "descriptions": [{"lang": "en", "value":
                          "In the Linux kernel, the following vulnerability "
                          "has been resolved:\n\nfoo: fix bar\n\nDetails."}],
        "affected": [{
            "product": "Linux", "vendor": "Linux",
            "defaultStatus": default, "programFiles": files,
            "versions": versions,
        }],
        "references": [{"url": f"https://git.kernel.org/stable/c/{cve_id}"}],
    }
    if fixes:
        # the git ranges, one per mainline or stable fix commit
        cna["affected"].insert(0, {
            "product": "Linux", "vendor": "Linux",
            "defaultStatus": "unaffected", "programFiles": files,
            "versions": [{"version": "1" * 40, "lessThan": fix,
                          "status": "affected", "versionType": "git"}
                         for fix in fixes],
        })
    if severity:
        cna["metrics"] = [{"cvssV3_1": {
            "baseSeverity": severity,
            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}]
    return {"cveMetadata": {"cveId": cve_id,
                            "datePublished": "2026-10-01T00:00:00.000Z"},
            "containers": {"cna": cna}}


@pytest.mark.parametrize("deb, kernel", [
    (QLI_VERSION, "7.2.0"),
    ("7.3.0~rc4+git20261007~gba86f6790835-0qli1~bpo13+1", "7.3.0-rc4"),
    ("6.12.48-1", "6.12.48"),
    ("6.12.48-1~bpo12+1", "6.12.48"),
])
def test_deb_kernel_version(deb, kernel):
    assert str(kernel_cves.deb_kernel_version(deb)) == kernel


@pytest.mark.parametrize("version, affected", [
    ("5.15", False),      # before the bug was introduced
    ("6.6.10", True),     # stable branch, before its fix
    ("6.6.79", False),    # stable fix
    ("6.6.100", False),   # after the stable fix
    ("6.12.0", True),     # branch without a stable fix
    ("6.14.0-rc3", True),  # rc of the mainline fix release counts as before
    ("6.14.0", False),    # mainline fix
    ("7.2.0", False),
])
def test_cve_affects(version, affected):
    cve = record("CVE-2026-1", semver("5.19", "6.6.79", mainline="6.14"),
                 ["io_uring/kbuf.c"])
    numbers, _, rc = version.partition("-rc")
    kernel = kernel_cves.KernelVersion(map(int, numbers.split(".")),
                                       int(rc) if rc else None)
    assert kernel_cves.cve_affects(cve, kernel) is affected


def test_cve_affects_stable_only_bug():
    # a bug only a stable backport introduced, unaffected by default
    versions = [{"version": "6.6.50", "lessThan": "6.6.55",
                 "status": "affected", "versionType": "semver"}]
    cve = record("CVE-2026-2", versions, ["mm/foo.c"], default="unaffected")
    assert kernel_cves.cve_affects(cve, kernel_cves.deb_kernel_version(
        "6.6.52-1"))
    assert not kernel_cves.cve_affects(cve, kernel_cves.deb_kernel_version(
        QLI_VERSION))


def test_cve_affects_without_mainline_fix():
    # some records only have stable fixes; then later versions are affected
    cve = record("CVE-2021-3", semver("5.10", "5.17.2"), ["drivers/x.c"])
    assert kernel_cves.cve_affects(cve, kernel_cves.deb_kernel_version(
        QLI_VERSION))


@pytest.mark.parametrize("files, present", [
    (["drivers/gpu/drm/amd/amdgpu/amdgpu.c"], []),
    (["net/core/dev.c", "drivers/x.c"], ["net/core/dev.c"]),
    (["include/linux/skbuff.h"], ["include/linux/skbuff.h"]),
    (["include/linux/foo.h"], []),
    (["Documentation/foo.rst", "drivers/x.c"], []),
    # files other than code may be compiled, e.g. device trees
    (["arch/arm64/boot/dts/qcom/x.dtsi"], ["arch/arm64/boot/dts/qcom/x.dtsi"]),
    (["drivers/x/Makefile"], ["drivers/x/Makefile"]),
])
def test_compiled(files, present):
    sources = {"net/core/dev.c", "include/linux/skbuff.h"}
    assert kernel_cves.compiled(files, sources) == present


def write_inputs(tmp_path, records, version=QLI_VERSION):
    for cve in records:
        cve_id = cve["cveMetadata"]["cveId"]
        path = tmp_path / "vulns" / "cve" / "published" / \
            cve_id.split("-")[1] / f"{cve_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cve))
    debs = [{"type": "deb", "name": name, "version": version,
             "metadata": {"source": "linux-qcom-7.2"}}
            for name in ("linux-image-qcom-7.2", "linux-headers-qcom-7.2")]
    debs.append({"type": "deb", "name": "bash", "version": "5.2.37-2",
                 "metadata": {"source": "bash"}})
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({
        "artifacts": debs,
        "distro": {"id": "debian", "versionID": "13.7",
                   "versionCodename": "trixie"}}))
    sources = tmp_path / "sources.txt"
    sources.write_text("net/core/dev.c\ninclude/linux/skbuff.h\n")
    return sbom, sources


def test_run(tmp_path):
    sbom, sources = write_inputs(tmp_path, [
        record("CVE-2026-10", semver("5.4", mainline="7.3"),
               ["net/core/dev.c"], severity="HIGH"),
        record("CVE-2026-11", semver("5.4", mainline="7.3"),
               ["drivers/gpu/drm/amd/amdgpu/amdgpu.c"]),
        record("CVE-2026-12", semver("5.4", mainline="7.1"),
               ["net/core/dev.c"]),
    ])
    result = subprocess.run(
        [sys.executable, SCRIPT, "--vulns", str(tmp_path / "vulns"),
         "--sbom", str(sbom), "--compiled-sources", str(sources),
         "--osv-dir", str(tmp_path / "osv"),
         "--vex", str(tmp_path / "kernel.openvex.json")],
        check=True, capture_output=True, text=True)
    assert "3 kernel CVEs, 2 affect the version" in result.stdout
    assert "1 of them change no compiled file" in result.stdout
    assert "1 open: 1 high" in result.stdout

    osv_dir = tmp_path / "osv" / f"linux-qcom-7.2_{QLI_VERSION}"
    assert sorted(os.listdir(osv_dir)) == [
        "CVE-2026-10.osv.json", "CVE-2026-11.osv.json"]
    osv = json.loads((osv_dir / "CVE-2026-10.osv.json").read_text())
    assert osv["summary"] == "foo: fix bar"
    assert osv["database_specific"] == {"severity": "high"}
    assert osv["affected"] == [{
        "package": {"ecosystem": "Debian:13", "name": "linux-qcom-7.2"},
        "versions": [QLI_VERSION],
    }]

    vex = json.loads((tmp_path / "kernel.openvex.json").read_text())
    statement, = vex["statements"]
    assert statement["vulnerability"] == {"name": "CVE-2026-11"}
    assert statement["status"] == "not_affected"
    assert statement["justification"] == "vulnerable_code_not_present"
    assert statement["products"] == [{
        "@id": "pkg:generic/qualcomm-linux-debian-rootfs",
        "subcomponents": [
            {"@id": f"pkg:deb/debian/linux-headers-qcom-7.2@{QLI_VERSION}"},
            {"@id": f"pkg:deb/debian/linux-image-qcom-7.2@{QLI_VERSION}"},
        ]}]


def test_run_without_kernel(tmp_path):
    sbom, _ = write_inputs(tmp_path, [
        record("CVE-2026-10", semver("5.4", mainline="7.3"),
               ["net/core/dev.c"])])
    result = subprocess.run(
        [sys.executable, SCRIPT, "--vulns", str(tmp_path / "vulns"),
         "--sbom", str(sbom), "--source", "linux"],
        check=False, capture_output=True, text=True)
    assert result.returncode == 1
    assert "no kernel packages in the SBOM" in result.stderr


def run_script(*args):
    return subprocess.run([sys.executable, SCRIPT, *map(str, args)],
                          check=False, capture_output=True, text=True)


def add_debian_kernel(sbom):
    data = json.loads(sbom.read_text())
    data["artifacts"].append({"type": "deb", "name": "linux-image-arm64",
                              "version": "6.12.48-1",
                              "metadata": {"source": "linux"}})
    sbom.write_text(json.dumps(data))


def test_list_kernels(tmp_path):
    # Debian's kernel is the Debian security tracker's
    sbom, _ = write_inputs(tmp_path, [])
    add_debian_kernel(sbom)
    result = run_script("--list-kernels", "--sbom", sbom)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"linux-qcom-7.2_{QLI_VERSION}\n"
    result = run_script("--list-kernels", "--sbom", sbom, "--source", "linux")
    assert result.stdout == "linux_6.12.48-1\n"


def test_compiled_sources_directory(tmp_path):
    # the lists of pkg-linux-qcom's artifacts, named after the kernels
    sbom, sources = write_inputs(tmp_path, [
        record("CVE-2026-11", semver("5.4", mainline="7.3"),
               ["drivers/gpu/drm/amd/amdgpu/amdgpu.c"])])
    lists = tmp_path / "compiled-sources"
    lists.mkdir()
    sources.rename(lists / f"linux-qcom-7.2_{QLI_VERSION}"
                   ".compiled-sources.txt")
    vex = tmp_path / "kernel.openvex.json"
    result = run_script("--vulns", tmp_path / "vulns", "--sbom", sbom,
                        "--compiled-sources", lists, "--vex", vex)
    assert result.returncode == 0, result.stderr
    assert "1 of them change no compiled file" in result.stdout
    assert len(json.loads(vex.read_text())["statements"]) == 1


def test_compiled_sources_missing(tmp_path):
    # without a list, e.g. an expired artifact, by version only, and no VEX
    sbom, _ = write_inputs(tmp_path, [
        record("CVE-2026-11", semver("5.4", mainline="7.3"),
               ["drivers/gpu/drm/amd/amdgpu/amdgpu.c"])])
    lists = tmp_path / "compiled-sources"
    lists.mkdir()
    vex = tmp_path / "kernel.openvex.json"
    result = run_script("--vulns", tmp_path / "vulns", "--sbom", sbom,
                        "--compiled-sources", lists, "--vex", vex)
    assert result.returncode == 0, result.stderr
    assert f"warning: no compiled sources for linux-qcom-7.2 {QLI_VERSION}" \
        in result.stdout
    assert "1 open: 1 unknown" in result.stdout
    assert not vex.exists()


def test_needs_vulns(tmp_path):
    sbom, _ = write_inputs(tmp_path, [])
    result = run_script("--sbom", sbom)
    assert result.returncode == 2
    assert "--vulns is required" in result.stderr


def git(repo, *args, date="2026-10-01T12:00:00Z"):
    env = dict(os.environ, GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date,
               GIT_AUTHOR_NAME="A", GIT_AUTHOR_EMAIL="a@example.com",
               GIT_COMMITTER_NAME="A", GIT_COMMITTER_EMAIL="a@example.com",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True,
                          env=env).stdout.strip()


def commit(repo, message, **kwargs):
    git(repo, "commit", "--quiet", "--allow-empty", "-m", message, **kwargs)
    return git(repo, "rev-parse", "HEAD")


def kernel_repository(tmp_path):
    # a kernel branch merging one upstream fix and backporting two others,
    # with git cherry-pick -x and the way the stable releases do
    repo = tmp_path / "kernel"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    commit(repo, "Linux 7.2")
    git(repo, "tag", "v7.2")
    git(repo, "checkout", "--quiet", "-b", "upstream")
    merged = commit(repo, "net: fix merged")
    picked = commit(repo, "mm: fix cherry-picked")
    stable = commit(repo, "fs: fix backported to stable")
    git(repo, "checkout", "--quiet", "main")
    git(repo, "merge", "--quiet", "--no-ff", "-m", "Merge fixes", merged)
    commit(repo, f"mm: fix cherry-picked\n\n(cherry picked from commit "
                 f"{picked})")
    head = commit(repo, f"fs: fix backported\n\ncommit {stable} upstream.")
    return repo, head, {"merged": merged, "picked": picked,
                        "stable": stable}


def test_fix_commits(tmp_path):
    repo, head, fixes = kernel_repository(tmp_path)
    version = f"7.2.0+git20261008~g{head[:12]}-0qli1~bpo13+1"
    sbom, _ = write_inputs(tmp_path, [
        record("CVE-2026-20", semver("5.4", mainline="7.3"), ["net/a.c"],
               fixes=["2" * 40, fixes["merged"]]),
        record("CVE-2026-21", semver("5.4", mainline="7.3"), ["mm/b.c"],
               fixes=[fixes["picked"]]),
        record("CVE-2026-22", semver("5.4", mainline="7.3"), ["fs/c.c"],
               fixes=[fixes["stable"]]),
        # not in the history
        record("CVE-2026-23", semver("5.4", mainline="7.3"), ["fs/d.c"],
               fixes=["3" * 40]),
    ], version=version)
    vex = tmp_path / "kernel.openvex.json"
    result = run_script("--vulns", tmp_path / "vulns", "--sbom", sbom,
                        "--kernel-repository", f"file://{repo}",
                        "--vex", vex)
    assert result.returncode == 0, result.stderr
    assert "4 kernel CVEs, 4 affect the version" in result.stdout
    assert f"3 of them fixed by commits of the build, {head[:12]} " \
        "(2 backported; history since 2025-12-31, 274 days before v7.2): " \
        "fixed" in result.stdout
    assert "1 open: 1 unknown" in result.stdout
    statements = {s["vulnerability"]["name"]: s
                  for s in json.loads(vex.read_text())["statements"]}
    assert sorted(statements) == ["CVE-2026-20", "CVE-2026-21",
                                  "CVE-2026-22"]
    assert all(s["status"] == "fixed" for s in statements.values())
    assert statements["CVE-2026-20"]["status_notes"].startswith(
        f"The fix {fixes['merged']} is in linux-qcom-7.2 {version}, built "
        f"from {head} (")
    assert "which backports it" in \
        statements["CVE-2026-21"]["status_notes"]
    assert statements["CVE-2026-21"]["products"][0]["subcomponents"][0] == \
        {"@id": f"pkg:deb/debian/linux-headers-qcom-7.2@{version}"}


def test_fix_commits_without_build_commit(tmp_path):
    # e.g. Debian's kernel versions name no commit
    repo, _, fixes = kernel_repository(tmp_path)
    sbom, _ = write_inputs(tmp_path, [
        record("CVE-2026-20", semver("5.4", mainline="7.3"), ["net/a.c"],
               fixes=[fixes["merged"]])], version="7.2.0-1")
    result = run_script("--vulns", tmp_path / "vulns", "--sbom", sbom,
                        "--kernel-repository", f"file://{repo}")
    assert result.returncode == 0, result.stderr
    assert "warning: no history of linux-qcom-7.2 7.2.0-1" in result.stdout
    assert "no build commit in the package version" in result.stdout
    assert "1 open" in result.stdout


@pytest.mark.parametrize("message", [
    "x\n\n(cherry picked from commit {sha})",
    "x\n\n(cherry picked from commit {short})",
    "x\n\ncommit {sha} upstream.\n\nbody",
    "x\n\n[ Upstream commit {sha} ]",
    "x\n\n(backported from commit {sha})",
])
def test_backport_trailers(message):
    sha = "ab" * 20
    log = "9" * 40 + "\0" + message.format(sha=sha, short=sha[:12]) + "\0\n"
    history = kernel_cves.KernelHistory("9" * 40, log)
    assert history.fix(["cd" * 20, sha]) == (sha, "9" * 40)
    if "{sha}" in message:
        # only the backported commit, not one starting like it
        assert history.fix(["ab" * 6 + "cd" * 14]) is None


def old_base_repository(tmp_path, tag=True):
    # a branch of a release of 2024, built in 2026, with a fix merged in 2024
    repo = tmp_path / "kernel"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    commit(repo, "Linux 6.6", date="2024-01-01T00:00:00Z")
    if tag:
        git(repo, "tag", "v6.6")
    git(repo, "checkout", "--quiet", "-b", "upstream")
    fix = commit(repo, "net: fix", date="2023-12-01T00:00:00Z")
    git(repo, "checkout", "--quiet", "main")
    git(repo, "merge", "--quiet", "--no-ff", "-m", "Merge fix", fix,
        date="2024-02-01T00:00:00Z")
    head = commit(repo, "arm64: dts: qcom: new board")
    version = f"6.6.0+git20261008~g{head[:12]}-0qli1~bpo13+1"
    sbom, _ = write_inputs(tmp_path, [
        record("CVE-2026-30", semver("5.4", mainline="6.7"), ["net/a.c"],
               fixes=[fix])], version=version)
    return repo, sbom


def test_fix_commits_history_from_base_tag(tmp_path):
    # the history starts before the release the kernel is based on, however
    # old, not before its build
    repo, sbom = old_base_repository(tmp_path)
    result = run_script("--vulns", tmp_path / "vulns", "--sbom", sbom,
                        "--kernel-repository", f"file://{repo}")
    assert result.returncode == 0, result.stderr
    assert "1 of them fixed by commits of the build" in result.stdout
    assert "history since 2023-04-02, 274 days before v6.6" in result.stdout
    assert "0 open" in result.stdout


def test_fix_commits_history_without_base_tag(tmp_path):
    # without the tag, the year before the build date, missing the old fix
    repo, sbom = old_base_repository(tmp_path, tag=False)
    result = run_script("--vulns", tmp_path / "vulns", "--sbom", sbom,
                        "--kernel-repository", f"file://{repo}")
    assert result.returncode == 0, result.stderr
    assert "0 of them fixed by commits of the build" in result.stdout
    assert "history since 2025-10-08, 365 days before the build date, " \
        "without v6.6" in result.stdout
    assert "1 open" in result.stdout


@pytest.mark.parametrize("version, tag", [
    ("7.3.0", "v7.3"), ("7.3.5", "v7.3"), ("7.3.0-rc4", "v7.3-rc4"),
    ("2.6.32.1", "v2.6.32"),
])
def test_base_tag(version, tag):
    numbers, _, rc = version.partition("-rc")
    kernel = kernel_cves.KernelVersion(map(int, numbers.split(".")),
                                       int(rc) if rc else None)
    assert kernel_cves.base_tag(kernel) == tag
