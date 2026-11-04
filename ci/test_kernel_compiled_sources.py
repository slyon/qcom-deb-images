"""Tests for the compiled kernel sources lists"""

# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

import importlib.util
import os
import subprocess
import sys

TOP = os.path.join(os.path.dirname(__file__), os.pardir)
SCRIPT = os.path.join(TOP, "scripts", "kernel-compiled-sources.py")
RECIPE = os.path.join(TOP, "debos-recipes",
                      "qualcomm-linux-debian-rootfs.yaml")

spec = importlib.util.spec_from_file_location("kernel_compiled_sources",
                                              SCRIPT)
kcs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kcs)

BUILD = "/build/reproducible-path/linux-qcom-next-7.3.0"

# readelf --debug-dump=rawline excerpts: a DWARF 5 line program with the
# forms in the entries, one with the forms in columns of their own, and a
# DWARF 4 one
READELF = f"""
 The Directory Table (offset 0x22, lines 3, columns 1):
  Entry\tName
  0\t(indirect line string, offset: 0x56): {BUILD}
  1\t(indirect line string, offset: 0x9f): lib
  2\t(indirect line string, offset: 0xa3): /usr/lib/gcc/aarch64/14/include

 The File Name Table (offset 0x5d, lines 4, columns 2):
  Entry\tDir\tName
  0\t1\t(indirect line string, offset: 0x1a3): ts_kmp.c
  1\t1\t(indirect line string, offset: 0x1ac): ts_kmp.c
  2\t2\t(indirect line string, offset: 0x1b5): stddef.h
  3\t0\t(indirect line string, offset: 0x1c0): <built-in>

 Line Number Statements:
  [0x00000080]  Set column to 1

 The Directory Table (offset 0x89, lines 2, columns 1):
  Entry\tName
  0\t(line_strp)\t(offset: 0x0): {BUILD}
  1\t(line_strp)\t(offset: 0x244): ./include/linux

 The File Name Table (offset 0x99, lines 2, columns 2):
  Entry\tDir\tName
  0\t(udata)\t0\t(line_strp)\t(offset: 0xa978): init/main.c
  1\t(udata)\t1\t(line_strp)\t(offset: 0x254): init.h

 The Directory Table (offset 0x11, lines 1):
  1\tnet/core

 The File Name Table (offset 0x22, lines 1):
  Entry\tDir\tTime\tSize\tName
  1\t1\t0\t0\tdev.c
"""


def test_source_files(monkeypatch):
    def readelf(*_, **__):
        return subprocess.CompletedProcess([], 0, stdout=READELF)
    monkeypatch.setattr(kcs.subprocess, "run", readelf)
    assert kcs.source_files("vmlinux", []) == {
        "lib/ts_kmp.c", "init/main.c", "include/linux/init.h",
        "net/core/dev.c"}


def test_read_qli_source():
    # the source the images are built with
    uri, key = kcs.read_qli_source(RECIPE)
    assert uri == "https://deb.debusine.qualcomm.com/qualcomm/qli"
    assert key[0] == " -----BEGIN PGP PUBLIC KEY BLOCK-----"
    assert key[-1] == " -----END PGP PUBLIC KEY BLOCK-----"
    assert all(line.startswith(" ") for line in key)


def deb(name, version, source, architecture="arm64"):
    return {"type": "deb", "name": name, "version": version,
            "metadata": {"source": source, "architecture": architecture}}


def test_sbom_kernels():
    version = "7.3.0+git20261030~gae2606baf50f-0qli1~bpo13+1"
    sbom = {"artifacts": [
        deb("linux-image-7.3.0+qcom-next-20261030-gae2606baf50f", version,
            "linux-qcom-next"),
        deb("linux-image-qcom-next", version, "linux-qcom-next"),
        deb("linux-headers-qcom-next", version, "linux-qcom-next"),
        # Debian's kernel is the Debian security tracker's
        deb("linux-image-arm64", "6.12.48-1", "linux"),
        deb("bash", "5.2.37-2", "bash"),
    ]}
    assert kcs.sbom_kernels(sbom) == {
        ("linux-qcom-next", version): ("arm64", [
            "linux-image-7.3.0+qcom-next-20261030-gae2606baf50f",
            "linux-image-qcom-next"]),
    }


def test_needs_paths_or_sbom():
    result = subprocess.run([sys.executable, SCRIPT], check=False,
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert "give either paths or --sbom" in result.stderr
