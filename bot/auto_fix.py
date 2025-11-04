from github import Github
import os
import json
from datetime import datetime

# Load parsed Trivy JSON
parsed_file = os.path.join(os.path.dirname(__file__), "trivy-parsed.json")
with open(parsed_file) as f:
    data = json.load(f)

vulns = data["HIGH"] + data["CRITICAL"]

if not vulns:
    print("No HIGH or CRITICAL vulnerabilities, skipping PR.")
    exit(0)

# Authenticate to GitHub
token = os.environ.get("GH_TOKEN")
g = Github(token)
repo_name = os.environ.get("GITHUB_REPOSITORY")
repo = g.get_repo(repo_name)

# Dynamic branch name
branch_name = f"auto-fix-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
source = repo.get_branch("main")
try:
    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source.commit.sha)
except:
    print(f"Branch {branch_name} already exists, continuing...")

# Real fix logic example
requirements_file = "requirements.txt"
if os.path.exists(requirements_file):
    with open(requirements_file, "r") as f:
        lines = f.readlines()

    with open(requirements_file, "w") as f:
        for line in lines:
            pkg_name = line.split("==")[0].strip()
            for v in vulns:
                if v.get("PkgName") == pkg_name:
                    fixed_version = v.get("FixedVersion")
                    if fixed_version:
                        line = f"{pkg_name}=={fixed_version}\n"
            f.write(line)

# Fallback dummy fix
dummy_file_path = "fix_dummy.txt"
with open(dummy_file_path, "w") as f:
    f.write("Placeholder fix for HIGH/CRITICAL vulnerabilities.\n")

# Dynamic PR description
pr_body = "This PR is created by DevSecOps Bot.\n\n"
if data["HIGH"]:
    pr_body += f"**HIGH vulnerabilities ({len(data['HIGH'])}):**\n"
    for v in data["HIGH"]:
        pr_body += f"- {v.get('PkgName')} ({v.get('VulnerabilityID')})\n"

if data["CRITICAL"]:
    pr_body += f"\n**CRITICAL vulnerabilities ({len(data['CRITICAL'])}):**\n"
    for v in data["CRITICAL"]:
        pr_body += f"- {v.get('PkgName')} ({v.get('VulnerabilityID')})\n"

pr_title = f"Auto-Fix: {len(data['HIGH'])} HIGH / {len(data['CRITICAL'])} CRITICAL vulnerabilities"
try:
    repo.create_pull(title=pr_title, body=pr_body, head=branch_name, base="main")
    print("Pull request created ✅")
except:
    print("Pull request already exists or failed.")
