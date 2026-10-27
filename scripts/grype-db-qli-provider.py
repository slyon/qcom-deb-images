#!/usr/bin/env python3
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

# PROTOTYPE: generate a vunnel provider workspace ("qli") from our OSV
# advisories (advisories/*.osv.json on the security-tracker branch), so that
# Anchore's grype-db can build a Grype vulnerability database including them,
# as another Debian data source, next to the data of Anchore's providers.
#
# The records use vunnel's "os" schema, like those of the Debian provider:
# one per advisory and Debian release, with a FixedIn entry per affected
# interval of each source package. Grype then matches them like the Debian
# security tracker's data, for every binary of the source package.
#
# Building a database, see .github/grype-db.yaml:
#
#   # Anchore's daily provider data, public on ghcr.io, e.g. with oras:
#   for p in debian nvd epss kev eol; do
#       oras pull ghcr.io/anchore/grype-db/data/$p:latest
#       grype-db cache restore --path .cache/vunnel/$p/grype-db-cache.tar.gz
#   done
#   repo=https://github.com/qualcomm-linux/qcom-deb-images
#   scripts/grype-db-qli-provider.py --source-root .security-tracker \
#       --source-url "$repo/blob/<commit>/" \
#       data/qli .security-tracker/advisories/*.osv.json
#   grype-db build -c .github/grype-db.yaml --dir build --schema 6
#   grype-db package -c .github/grype-db.yaml --dir build
#   grype db import build/vulnerability-db_*.tar.zst
#
# The build takes about 70 minutes, mostly for the NVD data, and gives a
# ~1GB database, whose findings for Debian packages match those of Anchore's
# database, plus those of the advisories.

import argparse
import csv
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone

PROVIDER = "qli"
RECORD_SCHEMA = ("https://raw.githubusercontent.com/anchore/vunnel/main/"
                 "schema/vulnerability/os/schema-1.1.0.json")
STATE_SCHEMA = ("https://raw.githubusercontent.com/anchore/vunnel/main/"
                "schema/provider-workspace-state/schema-1.0.3.json")
# from distro-info-data
DISTRO_INFO = "/usr/share/distro-info/debian.csv"


def load_releases(path):
    # the Debian releases of distro-info-data, as the OSV Debian ecosystem
    # names them: by version, e.g. "13", or by series for those without one,
    # e.g. "sid"
    with open(path, encoding="utf-8", newline="") as f:
        return {row["version"] or row["series"]: row
                for row in csv.DictReader(f)}


def namespaces(ecosystem, releases):
    # the vunnel namespaces of an OSV Debian ecosystem: Debian:<version> is
    # debian:<version>, and debian:unstable too while it's testing, i.e. not
    # released yet, as Grype matches testing as unstable; Debian:sid is
    # debian:unstable; Debian is every release
    name, _, release = ecosystem.partition(":")
    if name != "Debian":
        raise ValueError(f"unsupported ecosystem {ecosystem!r}")
    if not release:
        return sorted({ns for key in releases
                       for ns in namespaces(f"Debian:{key}", releases)})
    if release not in releases:
        raise ValueError(f"unknown Debian release {release!r}")
    row = releases[release]
    if not row["version"]:
        return ["debian:unstable"] if row["series"] == "sid" else []
    result = [f"debian:{row['version']}"]
    if not row.get("release"):
        result.append("debian:unstable")
    return result


def intervals(osv_range):
    # (introduced, end kind, end version) for each interval of an OSV
    # ECOSYSTEM range, validated on the security-tracker branch already
    pairs = []
    for event in osv_range["events"]:
        (kind, version), = event.items()
        if kind == "introduced":
            pairs.append((version, None, None))
        elif pairs and pairs[-1][1] is None:
            pairs[-1] = (pairs[-1][0], kind, version)
        else:
            raise ValueError(f"unsupported range event {kind!r}")
    return pairs


def fixed_in(source, namespace, introduced, kind, version):
    # an affected interval as the "os" schema has it: the fixed version, or
    # "None" while there is none, and the vulnerable range, which Grype uses
    # rather than "< fixed version" when given
    constraint = [] if introduced == "0" else [f">= {introduced}"]
    if kind == "fixed":
        constraint.append(f"< {version}")
    elif kind == "last_affected":
        constraint.append(f"<= {version}")
    return {
        "Name": source,
        "NamespaceName": namespace,
        "VersionFormat": "dpkg",
        "Version": version if kind == "fixed" else "None",
        "VulnerableRange": ", ".join(constraint),
        "VendorAdvisory": {"NoAdvisory": False, "AdvisorySummary": []},
    }


def records(advisory, releases, source_url):
    # (identifier, record) for each Debian release of an advisory
    by_namespace = {}
    for entry in advisory["affected"]:
        if "ecosystem_specific" in entry:
            raise ValueError("ecosystem_specific is not supported")
        source = entry["package"]["name"]
        for namespace in namespaces(entry["package"]["ecosystem"], releases):
            for osv_range in entry["ranges"]:
                if osv_range.get("type") != "ECOSYSTEM":
                    raise ValueError("only ECOSYSTEM ranges are supported")
                by_namespace.setdefault(namespace, []).extend(
                    fixed_in(source, namespace, *interval)
                    for interval in intervals(osv_range))
    cves = [alias for alias in advisory.get("aliases") or []
            if alias.startswith("CVE-")]
    description = "\n\n".join(filter(None, (
        advisory.get("summary", "").strip(),
        advisory.get("details", "").strip())))
    for namespace, fixed in sorted(by_namespace.items()):
        identifier = f"{namespace}/{advisory['id'].lower()}"
        yield identifier, {"Vulnerability": {
            "Name": advisory["id"],
            "NamespaceName": namespace,
            "Description": description,
            # Grype reports it, as for the Debian security tracker's data
            "Severity": advisory["database_specific"]["severity"],
            # Grype reports the first reference as the data source
            "Link": source_url,
            "CVSS": [{"vector_string": severity["score"],
                      "version": severity["score"].split("/")[0]
                      .partition(":")[2]}
                     for severity in advisory.get("severity") or []
                     if severity.get("type") in ("CVSS_V3", "CVSS_V4")],
            "FixedIn": fixed,
            # Grype reports advisories with a CVE as the CVE with --by-cve
            "Metadata": {"Issued": advisory.get("published", ""),
                         "Updated": advisory["modified"],
                         "CVE": [{"Name": cve, "Link": ""} for cve in cves]},
        }}


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_workspace(workspace, items, urls):
    # the layout of a vunnel provider workspace with a sqlite store: grype-db
    # reads metadata.json, and verifies the results against the listing
    results = os.path.join(workspace, "results")
    os.makedirs(results, exist_ok=True)
    db_path = os.path.join(results, "results.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE results (id VARCHAR NOT NULL, record BLOB, "
                   "PRIMARY KEY (id))")
        for identifier, item in items:
            db.execute("INSERT INTO results VALUES (?, ?)", (
                identifier, json.dumps({"schema": RECORD_SCHEMA,
                                        "identifier": identifier,
                                        "item": item}).encode()))
    db.close()

    # grype-db takes the hash algorithm from the listing's extension, sha256
    # rather than vunnel's xxh64, which needs no module outside of the
    # standard library
    listing = os.path.join(workspace, "checksums.sha256")
    with open(listing, "w", encoding="utf-8") as f:
        f.write(f"{sha256_of(db_path)}  results/results.db\n")
    with open(os.path.join(workspace, "metadata.json"), "w",
              encoding="utf-8") as f:
        json.dump({
            "provider": PROVIDER,
            "urls": urls,
            "store": "sqlite",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "distribution_version": 1,
            "processor": os.path.basename(__file__),
            "listing": {"digest": sha256_of(listing),
                        "path": "checksums.sha256", "algorithm": "sha256"},
            "schema": {"version": "1.0.3", "url": STATE_SCHEMA},
            "stale": False,
        }, f, indent=2)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a vunnel provider workspace from QLI OSV "
                    "advisories, for grype-db (prototype).")
    parser.add_argument("workspace", help="provider workspace, e.g. data/qli")
    parser.add_argument("advisories", nargs="*", help="*.osv.json files")
    parser.add_argument("--distro-info", default=DISTRO_INFO,
                        help="Debian releases of distro-info-data "
                             "(default: %(default)s)")
    parser.add_argument("--source-url", default="",
                        help="URL prefix of the advisories' published "
                             "location, followed by their path relative to "
                             "--source-root; reported by Grype as the data "
                             "source of their findings")
    parser.add_argument("--source-root", default=".",
                        help="the directory --source-url points at "
                             "(default: the current one)")
    args = parser.parse_args()

    releases = load_releases(args.distro_info)
    items = []
    for path in args.advisories:
        with open(path, encoding="utf-8") as f:
            advisory = json.load(f)
        if advisory.get("withdrawn"):
            continue
        source_url = args.source_url + os.path.relpath(path,
                                                       args.source_root)
        try:
            items.extend(records(advisory, releases, source_url))
        except (KeyError, TypeError, ValueError) as error:
            parser.error(f"{path}: {error}")
    write_workspace(args.workspace, items,
                    [args.source_url] if args.source_url else [])
    print(f"{len(items)} records from {len(args.advisories)} advisories")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
