# DevSecOps Auto-Fix Bot

![DevSecOps Scan](https://github.com/Vasu-710/devsecops-autofix-bot/actions/workflows/scan.yml/badge.svg)

## One-liner
Automatically scans your GitHub repository for HIGH and CRITICAL vulnerabilities, parses the results, and creates automatic pull requests to fix them.

---

## Features
- Scans the repository using **Trivy** for vulnerabilities
- Parses HIGH and CRITICAL vulnerabilities using Python
- Automatically creates branches and pull requests with fixes
- Generates dynamic pull request descriptions with vulnerability details
- Uploads parsed JSON as an artifact for reference

---

## Architecture / Workflow
Push code → GitHub Actions triggers → Trivy scan → JSON parse → Auto-fix PR → Artifact upload

---



## Setup Instructions
1. Clone the repository:
```bash
git clone https://github.com/Vasu-710/devsecops-autofix-bot.git
cd devsecops-autofix-bot
```
2.Install dependencies:
```bash
pip install -r requirements.txt
pip install PyGithub
```
3. Set a GitHub token secret (GH_TOKEN) in your repository settings.
4. Push changes to the main branch → workflow runs automatically.
Usage Example
---
## Usage
Push any code to the main branch and the bot will scan your repository.
If HIGH or CRITICAL vulnerabilities are found, the bot will create a pull request with suggested fixes.
The parsed JSON file is uploaded as an artifact and can be downloaded from the Actions tab for inspection.
---
## Tech Stack
- Python 3.11 — scripts and parser
- Trivy — vulnerability scanning
- GitHub Actions — CI/CD workflow
- PyGithub — GitHub API integration
---
## Future Enhancements
- Slack or Teams notifications when a pull request is created
- HTML reports summarizing vulnerabilities
- Auto-comment CVE links in pull requests
- Automatic updates for dependencies in other programming languages
---
## Comments
Made by Vasu Saini 💻

