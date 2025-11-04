from github import Github   # import PyGithub library to talk to GitHub
import os
import json

# 1. Load parsed Trivy JSON
parsed_file = os.path.join(os.path.dirname(__file__), "../trivy-parsed.json")
with open(parsed_file) as f:
    data = json.load(f)

# 2. Check if there are HIGH/CRITICAL vulnerabilities
if not data["HIGH"] and not data["CRITICAL"]:
    print("No HIGH or CRITICAL vulnerabilities, skipping PR.")
    exit(0)

# 3. Authenticate to GitHub using token from secret
token = os.environ.get("GH_TOKEN")
g = Github(token)
repo_name = os.environ.get("GITHUB_REPOSITORY")  # GitHub Actions sets this automatically
repo = g.get_repo(repo_name)

# 4. Create a new branch from main
source = repo.get_branch("main")
branch_name = "auto-fix-demo"
try:
    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=source.commit.sha)
except:
    print(f"Branch {branch_name} already exists, continuing...")

# 5. Add a dummy fix file
file_path = "fix_dummy.txt"
file_content = "This is a placeholder fix for HIGH/CRITICAL vulnerabilities.\n"
try:
    repo.create_file(file_path, "Add dummy fix file", file_content, branch=branch_name)
except:
    contents = repo.get_contents(file_path, ref=branch_name)
    repo.update_file(contents.path, "Update dummy fix", file_content, contents.sha, branch=branch_name)

# 6. Open a pull request
pr_title = "Auto-Fix: HIGH/CRITICAL Vulnerabilities"
pr_body = "This PR is created by DevSecOps Bot as a demo to fix detected vulnerabilities."
try:
    repo.create_pull(title=pr_title, body=pr_body, head=branch_name, base="main")
    print("Pull request created ✅")
except:
    print("Pull request already exists or failed.")
