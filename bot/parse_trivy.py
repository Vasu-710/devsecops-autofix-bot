"""Split Trivy's findings into HIGH and CRITICAL lists for the fixer.

Trivy reports findings per result section, and the same package can appear in
more than one section, so the same CVE can arrive several times. The fixer only
needs each one once.
"""

import json
import os
import sys

HERE = os.path.dirname(__file__)
RESULTS_PATH = os.path.join(HERE, "trivy-results.json")
PARSED_PATH = os.path.join(HERE, "trivy-parsed.json")

WANTED = ("HIGH", "CRITICAL")


def load_results(path):
    """Read Trivy's output, exiting with a clear message if it is unusable.

    A missing or malformed file means the scan step did not do what the
    workflow thinks it did. That has to stop the run, not be worked around.
    """
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        sys.exit(f"{path} does not exist. Did the Trivy scan step run?")
    except json.JSONDecodeError as e:
        sys.exit(f"{path} is not valid JSON: {e}")


def split_by_severity(data):
    """Return {"HIGH": [...], "CRITICAL": [...]}, with duplicates removed.

    A finding is identified by its severity, package and vulnerability ID.
    Without this, one CVE listed in two result sections would be counted twice
    and the pull request title would overstate how much was found.
    """
    buckets = {name: [] for name in WANTED}
    seen = set()

    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = vuln.get("Severity")
            if severity not in buckets:
                continue
            key = (severity, vuln.get("PkgName"), vuln.get("VulnerabilityID"))
            if key in seen:
                continue
            seen.add(key)
            buckets[severity].append(vuln)

    return buckets


def main():
    data = load_results(RESULTS_PATH)
    buckets = split_by_severity(data)

    for name in WANTED:
        print(f"{name} vulnerabilities: {len(buckets[name])}")

    with open(PARSED_PATH, "w") as f:
        json.dump(buckets, f, indent=2)

    print(f"Wrote {PARSED_PATH}")


if __name__ == "__main__":
    main()
