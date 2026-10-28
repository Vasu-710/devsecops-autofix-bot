"""
DevSecOps Auto-Fix Bot.

Reads the parsed Trivy findings, works out which pinned dependencies have a
fixed version available, commits the bumped requirements.txt to a new branch,
opens a pull request, and then checks that the pull request actually contains
the change.

If anything goes wrong the script exits non-zero so the workflow turns red.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone

from github import Auth, Github, GithubException

REQUIREMENTS_PATH = "requirements.txt"
BASE_BRANCH = "main"

SEPARATORS = ("===", "==", ">=", "<=", "~=", "!=", ">", "<")


def load_findings():
    parsed_file = os.path.join(os.path.dirname(__file__), "trivy-parsed.json")
    with open(parsed_file) as f:
        return json.load(f)


def parse_package_name(line):
    """
    Pull the package name out of one line of requirements.txt.

    Returns None for comments, blank lines and flags like -r other.txt.
    """
    text = line.split("#", 1)[0].strip()
    if not text or text.startswith("-"):
        return None
    for separator in SEPARATORS:
        if separator in text:
            return text.split(separator, 1)[0].strip()
    return text


def parse_pinned_version(line):
    """Return the version if the line is pinned with ==, otherwise None."""
    text = line.split("#", 1)[0].strip()
    if "==" not in text:
        return None
    return text.split("==", 1)[1].strip()


def version_key(version):
    """
    Sortable key for a version string.

    Good enough to compare release versions like 1.26.5 against 2.8.0.

    The third element of each tuple is True for a plain number and False when
    there is a trailing suffix, so that 2.0.0 sorts above 2.0.0rc1 rather than
    below it.
    """
    key = []
    for chunk in re.split(r"[._-]", version):
        match = re.match(r"^(\d+)(.*)$", chunk)
        if match:
            suffix = match.group(2)
            key.append((1, int(match.group(1)), suffix == "", suffix))
        else:
            key.append((0, 0, False, chunk))
    return key


def major_of(version):
    """First numeric component, or None if there isn't one."""
    match = re.match(r"^(\d+)", version or "")
    return int(match.group(1)) if match else None


def build_fix_map(findings):
    """
    Map package name -> the highest fixed version across all of its findings.

    A package can have several CVEs, each with its own FixedVersion, and
    Trivy sometimes lists more than one per CVE. Picking any single one is not
    enough: only the highest fixes all of them. Taking whichever happened to be
    processed last would leave known vulnerabilities in place.
    """
    fixes = {}
    for vuln in findings:
        name = vuln.get("PkgName")
        fixed = vuln.get("FixedVersion")
        if not name or not fixed:
            continue
        for candidate in (part.strip() for part in fixed.split(",") if part.strip()):
            current = fixes.get(name)
            if current is None or version_key(candidate) > version_key(current):
                fixes[name] = candidate
    return fixes


def apply_fixes(content, fixes):
    """Return the rewritten file and a list of change records."""
    changes = []
    output = []
    for line in content.splitlines(keepends=True):
        name = parse_package_name(line)
        if name and name in fixes:
            ending = "\n" if line.endswith("\n") else ""
            new_version = fixes[name]
            replacement = f"{name}=={new_version}{ending}"
            if replacement != line:
                old_version = parse_pinned_version(line)
                old_major = major_of(old_version)
                new_major = major_of(new_version)
                changes.append({
                    "name": name,
                    "before": line.strip(),
                    "after": replacement.strip(),
                    "old_version": old_version,
                    "new_version": new_version,
                    "major_bump": (
                        old_major is not None
                        and new_major is not None
                        and new_major != old_major
                    ),
                })
                output.append(replacement)
                continue
        output.append(line)
    return "".join(output), changes


def build_pr_body(findings, changes):
    lines = [
        "Opened automatically by the DevSecOps Auto-Fix Bot.",
        "",
        "### Changes",
        "",
    ]
    for change in changes:
        flag = "  **major version change, review before merging**" if change["major_bump"] else ""
        lines.append(f"- `{change['before']}` becomes `{change['after']}`{flag}")

    majors = [c for c in changes if c["major_bump"]]
    if majors:
        names = ", ".join(c["name"] for c in majors)
        lines += [
            "",
            f"> This patch crosses a major version boundary for {names}. "
            "Major releases can remove or change APIs, so this is not a drop-in "
            "upgrade and should be tested rather than merged on sight.",
        ]

    lines += [
        "",
        "Each package is pinned to the highest fixed version reported across all "
        "of its findings, so that one patch closes every CVE listed below rather "
        "than only the last one checked.",
    ]

    for severity in ("CRITICAL", "HIGH"):
        items = findings.get(severity, [])
        if items:
            lines += ["", f"### {severity} findings ({len(items)})", ""]
            for vuln in items:
                lines.append(f"- {vuln.get('PkgName')} {vuln.get('VulnerabilityID')}")

    return "\n".join(lines)


def main():
    findings = load_findings()
    high = findings.get("HIGH", [])
    critical = findings.get("CRITICAL", [])
    print(f"Trivy reported {len(high)} HIGH and {len(critical)} CRITICAL findings.")

    all_findings = high + critical
    if not all_findings:
        print("Nothing to fix. Exiting cleanly.")
        return

    fixes = build_fix_map(all_findings)
    if not fixes:
        print("Findings exist but none of them have a FixedVersion. Nothing to patch.")
        return
    for name in sorted(fixes):
        print(f"  highest fixed version for {name}: {fixes[name]}")

    token = os.environ.get("GH_TOKEN")
    if not token:
        sys.exit("GH_TOKEN is not set, so the bot cannot talk to GitHub.")

    repo_name = os.environ.get("GITHUB_REPOSITORY")
    if not repo_name:
        sys.exit("GITHUB_REPOSITORY is not set.")

    repo = Github(auth=Auth.Token(token)).get_repo(repo_name)

    # Read requirements.txt from GitHub, not from the runner's disk. The
    # runner's copy is thrown away when the job ends, so it is useless for
    # building a commit.
    try:
        current = repo.get_contents(REQUIREMENTS_PATH, ref=BASE_BRANCH)
    except GithubException as e:
        sys.exit(f"Could not read {REQUIREMENTS_PATH} from {BASE_BRANCH}: {e.status} {e.data}")

    original_text = current.decoded_content.decode()
    new_text, changes = apply_fixes(original_text, fixes)

    if not changes:
        print("Vulnerable packages were reported, but requirements.txt already")
        print("pins the fixed versions. No pull request needed.")
        return

    for change in changes:
        note = "  (MAJOR VERSION CHANGE)" if change["major_bump"] else ""
        print(f"  {change['before']}  ->  {change['after']}{note}")

    branch_name = f"auto-fix-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    base = repo.get_branch(BASE_BRANCH)

    try:
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base.commit.sha)
    except GithubException as e:
        sys.exit(f"Could not create branch {branch_name}: {e.status} {e.data}")
    print(f"Created branch {branch_name}")

    # This is the step that was missing before. Without it the branch stays
    # identical to main and GitHub refuses to open a pull request.
    noun = "dependency" if len(changes) == 1 else "dependencies"
    try:
        repo.update_file(
            path=REQUIREMENTS_PATH,
            message=f"Bump {len(changes)} vulnerable {noun}",
            content=new_text,
            sha=current.sha,
            branch=branch_name,
        )
    except GithubException as e:
        sys.exit(f"Could not commit to {branch_name}: {e.status} {e.data}")
    print(f"Committed {len(changes)} change(s) to {branch_name}")

    title = f"Auto-Fix: {len(high)} HIGH / {len(critical)} CRITICAL"
    try:
        pull = repo.create_pull(
            title=title,
            body=build_pr_body(findings, changes),
            head=branch_name,
            base=BASE_BRANCH,
        )
    except GithubException as e:
        sys.exit(f"Could not open the pull request: {e.status} {e.data}")

    # Check the result, not the attempt. A pull request object coming back
    # without an exception is not proof that it contains anything.
    pull = repo.get_pull(pull.number)
    if pull.changed_files < 1:
        sys.exit(
            f"PR #{pull.number} was created but contains no file changes. "
            "Treating this as a failure."
        )

    print(f"Opened PR #{pull.number} with {pull.changed_files} changed file(s)")
    print(pull.html_url)


if __name__ == "__main__":
    main()
