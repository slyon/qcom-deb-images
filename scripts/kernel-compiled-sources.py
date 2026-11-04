#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

# List the kernel source files compiled into a kernel build, from the DWARF
# debug info of its vmlinux and modules, as shipped by its linux-image-*-dbg
# package (the debug symbols; the -debug variants are kernels of their own,
# with -dbg packages of their own); one path per line, relative to the root of
# the kernel source tree, sorted, for scripts/kernel-cves.py.
#
# Either from debug files at hand, printing the list, or, with --sbom, for the
# kernels of an image: this downloads the -dbg package of each from the QLI
# APT repository, as configured by the image recipe (--recipe), with apt, which
# checks the signature of the repository and the checksum of the package, and
# writes the list to --output as <source>_<version>.compiled-sources.txt. A
# kernel without -dbg package there, e.g. a bindeb-pkg build or one removed
# from the repository by now, is only reported with a warning on stdout,
# prefixed with "warning:"; scripts/kernel-cves.py then assesses its CVEs by
# version alone. Debian's own kernel is left out, like there.
#
# This reads the file name tables of the DWARF line programs, rather than
# only the compile units, so that headers are listed too: GCC lists every file
# a compile unit takes code or declarations from, so a header missing from all
# of them contributes nothing to the build. Files outside the source tree,
# e.g. the compiler's own headers, are left out.
#
# Needs readelf, from binutils, and, with --sbom, apt and dpkg-deb.

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from concurrent.futures import ThreadPoolExecutor

# readelf --debug-dump=rawline prints, for each line program, a directory and
# a file name table; DWARF 5 numbers directories from 0 (the compilation
# directory), DWARF 4 from 1, with 0 implicitly being the compilation
# directory
TABLE_RE = re.compile(r"^ The (Directory|File Name) Table")
# DWARF 5 entries: "  1\t(indirect line string, offset: 0x9f): lib" or,
# depending on the DWARF forms, with the forms in columns of their own:
# "  0\t(udata)\t1\t(line_strp)\t(offset: 0xa978): main.c"; DWARF 4 entries:
# "  1\tlib" and "  1\t1\t0\t0\tts_kmp.c"
ENTRY_RE = re.compile(r"^  (\d+)\t(.*)$")
FORM_COLUMN_RE = re.compile(r"\([a-z0-9_]+\)")
FORM_RE = re.compile(r"^\([^)]*\): ")

# the image recipe's APT source of the QLI repository, a here-document
QLI_SOURCES_RE = re.compile(
    r"tee /etc/apt/sources\.list\.d/qli\.sources <<EOF\n(.*?)\n *EOF\n",
    re.DOTALL)
KERNEL_IMAGE_RE = re.compile(r"linux-image-.*")
# the kernels the Debian security tracker covers, see scripts/kernel-cves.py
DEBIAN_SOURCES = {"linux"}
SUFFIX = ".compiled-sources.txt"
NAME_RE = re.compile(r"[A-Za-z0-9.+~_-]+")


def is_debug_file(path):
    name = os.path.basename(path)
    return name.startswith("vmlinux") or ".ko" in name


def strip_form(value):
    return FORM_RE.sub("", value.strip())


def line_program_files(path):
    # (compilation directory or None, absolute or relative file path) of
    # every file name table entry
    output = subprocess.run(
        ["readelf", "--wide", "--debug-dump=rawline", path],
        check=True, capture_output=True, text=True, errors="replace").stdout
    table = None
    dirs = {}
    for line in output.splitlines():
        match = TABLE_RE.match(line)
        if match:
            table = match[1]
            if table == "Directory":
                dirs = {}
            continue
        match = ENTRY_RE.match(line)
        if not match or table is None:
            if not line.strip() or line.startswith("  Entry"):
                continue
            table = None
            continue
        index, rest = int(match[1]), match[2]
        fields = [field for field in rest.split("\t")
                  if not FORM_COLUMN_RE.fullmatch(field.strip())]
        if table == "Directory":
            dirs[index] = strip_form(fields[-1])
        else:
            name = strip_form(fields[-1])
            if name.startswith("<"):
                # e.g. <built-in>
                continue
            directory = dirs.get(int(fields[0]), "") if len(fields) > 1 \
                else ""
            yield dirs.get(0), os.path.join(directory, name)


def source_files(path, prefixes):
    files = set()
    for comp_dir, name in line_program_files(path):
        if os.path.isabs(name):
            for prefix in ([comp_dir] if comp_dir else []) + prefixes:
                if name.startswith(prefix.rstrip("/") + "/"):
                    name = os.path.relpath(name, prefix)
                    break
            else:
                # outside the source tree, e.g. the compiler's headers
                continue
        name = os.path.normpath(name)
        if not name.startswith(".."):
            files.add(name)
    return files


def find_debug_files(paths):
    debug_files = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                debug_files.extend(os.path.join(root, name)
                                   for name in names
                                   if is_debug_file(name))
        else:
            debug_files.append(path)
    return sorted(debug_files)


def compiled_sources(paths, prefixes, jobs):
    debug_files = find_debug_files(paths)
    if not debug_files:
        raise ValueError("no vmlinux or modules found")
    files = set()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        for result in pool.map(lambda path: source_files(path, prefixes),
                               debug_files):
            files |= result
    if not files:
        raise ValueError("no debug info found")
    return debug_files, files


def read_qli_source(recipe):
    # the URI and the Signed-By lines (the key, in deb822 form) of the image
    # recipe's QLI APT source
    with open(recipe, encoding="utf-8") as f:
        match = QLI_SOURCES_RE.search(f.read())
    if not match:
        raise ValueError(f"no QLI APT source in {recipe}")
    uri, key, field = None, [], None
    for line in textwrap.dedent(match[1]).splitlines():
        if line.startswith((" ", "\t")):
            if field == "Signed-By":
                key.append(line)
            continue
        field, _, value = line.partition(":")
        if field == "URIs":
            uri = value.strip()
    if not uri or not key:
        raise ValueError(f"incomplete QLI APT source in {recipe}")
    return uri, key


def sbom_kernels(sbom):
    # {(source, version): (architecture, [linux-image-* packages])} of the
    # kernels of an SBOM, but Debian's
    kernels = {}
    for artifact in sbom.get("artifacts", []):
        if artifact.get("type") != "deb" or \
                not KERNEL_IMAGE_RE.fullmatch(artifact["name"]):
            continue
        metadata = artifact.get("metadata") or {}
        source = metadata.get("source") or artifact["name"]
        if source in DEBIAN_SOURCES:
            continue
        key = (source, artifact["version"])
        architecture = metadata.get("architecture", "")
        kernels.setdefault(key, (architecture, []))[1].append(
            artifact["name"])
    return kernels


class Apt:
    # a throwaway APT configuration, holding only the QLI repository
    def __init__(self, root, uri, key, suite, architecture):
        self.root = root
        for path in ("etc/apt/sources.list.d", "etc/apt/preferences.d",
                     "var/lib/apt/lists/partial",
                     "var/cache/apt/archives/partial", "var/lib/dpkg"):
            os.makedirs(os.path.join(root, path), exist_ok=True)
        open(os.path.join(root, "var/lib/dpkg/status"), "w",
             encoding="utf-8").close()
        with open(os.path.join(root, "etc/apt/sources.list.d/qli.sources"),
                  "w", encoding="utf-8") as f:
            f.write("\n".join([
                "Types: deb", f"URIs: {uri}", f"Suites: {suite}",
                "Components: main", f"Architectures: {architecture}",
                "Signed-By:", *key]) + "\n")
        self.options = [
            "-o", f"Dir={root}",
            "-o", f"Dir::State::status={root}/var/lib/dpkg/status",
            "-o", "Dir::Etc::SourceList=/dev/null",
            "-o", f"APT::Architecture={architecture}",
            "-o", f"APT::Architectures={architecture}",
            "-o", "Debug::NoLocking=1",
        ]
        self.run("apt-get", "-q", "update")

    def run(self, command, *args, cwd=None, check=True):
        return subprocess.run([command, *self.options, *args], cwd=cwd,
                              check=check, capture_output=True, text=True)

    def has(self, package, version):
        # apt-cache show succeeds for unknown versions too
        result = self.run("apt-cache", "madison", package, check=False)
        return any([field.strip() for field in line.split("|")][:2] ==
                   [package, version] for line in result.stdout.splitlines())

    def download(self, package, version, directory):
        self.run("apt-get", "-q", "download", f"{package}={version}",
                 cwd=directory)
        debs = [name for name in os.listdir(directory)
                if name.endswith(".deb")]
        if len(debs) != 1:
            raise ValueError(f"downloaded {debs} for {package}")
        return os.path.join(directory, debs[0])


def fetch(args):
    with open(args.sbom, encoding="utf-8") as f:
        sbom = json.load(f)
    kernels = sbom_kernels(sbom)
    if not kernels:
        print("no kernel to list the compiled sources of")
        return 0
    suite = (sbom.get("distro") or {}).get("versionCodename")
    uri, key = read_qli_source(args.recipe)
    os.makedirs(args.output, exist_ok=True)
    apts = {}
    with tempfile.TemporaryDirectory() as tmp:
        for (source, version), (architecture, packages) in \
                sorted(kernels.items()):
            name = f"{source}_{version}"
            output = os.path.join(args.output, f"{name}{SUFFIX}")
            if not NAME_RE.fullmatch(name) or not suite or not architecture:
                print(f"warning: {name}: unexpected SBOM data, skipped")
                continue
            if os.path.exists(output):
                # from another image with the same kernel
                print(f"{name}: {output} already")
                continue
            work = tempfile.mkdtemp(dir=tmp)
            try:
                if architecture not in apts:
                    apts[architecture] = Apt(
                        os.path.join(tmp, f"apt-{architecture}"), uri, key,
                        suite, architecture)
                apt = apts[architecture]
                dbg = [f"{package}-dbg" for package in sorted(packages)
                       if apt.has(f"{package}-dbg", version)]
                if not dbg:
                    print(f"warning: {name}: no linux-image-*-dbg package in "
                          f"{uri} {suite}; assessing by version only")
                    continue
                deb = apt.download(dbg[0], version, work)
                subprocess.run(["dpkg-deb", "-x", deb,
                                os.path.join(work, "root")], check=True)
                debug_files, files = compiled_sources(
                    [os.path.join(work, "root")], args.prefix, args.jobs)
            except (OSError, ValueError,
                    subprocess.CalledProcessError) as error:
                detail = getattr(error, "stderr", None) or ""
                print(f"warning: {name}: cannot list the compiled sources: "
                      f"{error} {detail.strip()}; assessing by version only")
                continue
            finally:
                shutil.rmtree(work, ignore_errors=True)
            with open(output, "w", encoding="utf-8") as f:
                f.write("".join(f"{file}\n" for file in sorted(files)))
            print(f"{name}: {len(files)} source files, from "
                  f"{len(debug_files)} debug files of {dbg[0]}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="List the kernel source files compiled into a kernel, "
                    "from the DWARF debug info of its vmlinux and modules.")
    parser.add_argument("paths", nargs="*",
                        help="vmlinux and module files with debug info, or "
                             "directories to search for them, e.g. an "
                             "unpacked linux-image-*-dbg package")
    parser.add_argument("--sbom",
                        help="Syft JSON SBOM of an image, to list the "
                             "compiled sources of its kernels instead")
    parser.add_argument("--recipe",
                        default="debos-recipes/"
                                "qualcomm-linux-debian-rootfs.yaml",
                        help="image recipe configuring the QLI APT "
                             "repository, with --sbom (default: "
                             "%(default)s)")
    parser.add_argument("--output",
                        help="directory to write the lists to, with --sbom")
    parser.add_argument("--prefix", action="append", default=[],
                        help="absolute path of the kernel source tree at "
                             "build time, when it isn't the compilation "
                             "directory; may be given more than once")
    parser.add_argument("--jobs", type=int, default=os.cpu_count(),
                        help="readelf processes to run in parallel")
    args = parser.parse_args()
    if bool(args.sbom) == bool(args.paths):
        parser.error("give either paths or --sbom")
    if args.sbom and not args.output:
        parser.error("--sbom needs --output")

    try:
        if args.sbom:
            return fetch(args)
        debug_files, files = compiled_sources(args.paths, args.prefix,
                                              args.jobs)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"{len(debug_files)} debug files, {len(files)} source files",
          file=sys.stderr)
    for name in sorted(files):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
