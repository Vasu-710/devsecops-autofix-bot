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
import sys
from datetime import datetime, timezone

from github import Github, GithubException

REQUIREMENTS_PATH = "requirements.txt"
BASE_BRANCH = "main"


def load_findings():
    parsed_file = os.path.join(os.path.dirname(__file__), "trivy-parsed.json")
    with open(parsed_file) as f:
        return json.load(f)


def parse_package_name(line):
    """
    Pull the package name out of one line of requirements.txt.

    Handles ==, >=, <=, ~=, !=, > and <, plus bare names with no pin at all.
    Returns None for comments, blank lines and flags like -r other.txt.
    """
    text = line.split("#", 1)[0].strip()
    if not text or text.startswith("-"):
        return None
    for separator in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
        if separator in text:
            return text.split(separator, 1)[0].strip()
    return text


def build_fix_map(findings):
    """Map package name -> the version Trivy says is fixed."""
    fixes = {}
    for vuln in findings:
        name = vuln.get("PkgName")
        fixed = vuln.get("FixedVersion")
        if not name or not fixed:
            continue
        # FixedVersion is sometimes a comma separated list. Take the last one.
        fixes[name] = fixed.split(",")[-1].strip()
    return fixes


def apply_fixes(content, fixes):
    """Return the rewritten file and a list of (before, after) changes."""
    changes = []
    output = []
    for line in content.splitlines(keepends=True):
        name = parse_package_name(line)
        if name and name in fixes:
            ending = "\n" if line.endswith("\n") else ""
            replacement = f"{name}=={fixes[name]}{ending}"
            if replacement != line:
                changes.append((line.strip(), replacement.strip()))
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
    for before, after in changes:
        lines.append(f"- `{before}` becomes `{after}`")

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
    print(f"Packages with a fix available: {sorted(fixes)}")

    token = os.environ.get("GH_TOKEN")
    if not token:
        sys.exit("GH_TOKEN is not set, so the bot cannot talk to GitHub.")

    repo_name = os.environ.get("GITHUB_REPOSITORY")
    if not repo_name:
        sys.exit("GITHUB_REPOSITORY is not set.")

    repo = Github(token).get_repo(repo_name)

    # Read requirements.txt from GitHub, not from the runner's disk.
    # The runner's copy is thrown away when the job ends, so it is useless
    # for building a commit.
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

    for before, after in changes:
        print(f"  {before}  ->  {after}")

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
