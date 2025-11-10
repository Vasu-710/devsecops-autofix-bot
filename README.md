# 🤖 DevSecOps Auto-Fix Bot

![DevSecOps Scan](https://github.com/Vasu-710/devsecops-autofix-bot/actions/workflows/scan.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

> An intelligent automation bot that scans your GitHub repository for security vulnerabilities and automatically creates pull requests with fixes.

---

## 🎯 Overview

DevSecOps Auto-Fix Bot continuously monitors your repository for HIGH and CRITICAL security vulnerabilities using industry-standard scanning tools. When vulnerabilities are detected, the bot automatically generates fix recommendations and creates pull requests, streamlining your security workflow and reducing manual intervention.

---

## ✨ Key Features

- **🔍 Automated Security Scanning** - Leverages Trivy to detect vulnerabilities in dependencies
- **🎯 Smart Filtering** - Focuses on HIGH and CRITICAL severity issues
- **🔧 Automatic Fix Generation** - Creates branches with dependency version updates
- **📝 Detailed PR Descriptions** - Generates comprehensive pull requests with vulnerability breakdowns
- **📊 Artifact Storage** - Uploads parsed scan results for audit and analysis
- **⚡ CI/CD Integration** - Seamlessly integrates with GitHub Actions workflow

---

## 🏗️ Architecture

```
┌─────────────────┐
│   Code Push     │
│   to main       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ GitHub Actions  │
│    Triggered    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Trivy Scanner  │
│  (Vuln. Scan)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Parse Results  │
│ (parse_trivy.py)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Auto-Fix Bot  │
│ (auto_fix.py)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Create PR +    │
│ Upload Artifact │
└─────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- GitHub account with repository access
- GitHub Personal Access Token with `repo` permissions

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Vasu-710/devsecops-autofix-bot.git
   cd devsecops-autofix-bot
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure GitHub Token**
   - Navigate to your repository settings
   - Go to `Settings` → `Secrets and variables` → `Actions`
   - Add a new secret named `GH_TOKEN` with your GitHub Personal Access Token

4. **Trigger the workflow**
   ```bash
   git add .
   git commit -m "Initial setup"
   git push origin main
   ```

The workflow will automatically run on every push to the `main` branch.

---

## 📖 Usage

### Automatic Scanning

The bot automatically scans your repository when:
- Code is pushed to the `main` branch
- A pull request is merged into `main`

### Manual Trigger

You can also manually trigger the workflow from the GitHub Actions tab.

### Review Pull Requests

When vulnerabilities are found:
1. The bot creates a new branch with timestamp (e.g., `auto-fix-20250109-143052`)
2. A pull request is opened with detailed vulnerability information
3. Review the changes and merge if appropriate

### View Scan Results

Detailed scan artifacts are available in the Actions tab:
1. Navigate to `Actions` → Select the latest workflow run
2. Download the `trivy-parsed` artifact
3. Review the JSON file for complete vulnerability details

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| **Python 3.11** | Core scripting and automation logic |
| **Trivy** | Security vulnerability scanner |
| **GitHub Actions** | CI/CD automation and workflow orchestration |
| **PyGithub** | GitHub API integration for PR creation |

---

## 📁 Project Structure

```
devsecops-autofix-bot/
├── .github/
│   └── workflows/
│       └── scan.yml          # GitHub Actions workflow
├── bot/
│   ├── parse_trivy.py        # Trivy results parser
│   ├── auto_fix.py           # PR creation and fix logic
│   └── main.py               # Main orchestrator
├── tests/
│   └── tests.py              # Test suite (TBD)
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## 🔧 Configuration

### Scan Severity Levels

By default, the bot scans for HIGH and CRITICAL vulnerabilities. To modify:

Edit `.github/workflows/scan.yml`:
```yaml
severity: HIGH,CRITICAL,MEDIUM  # Add MEDIUM severity
```

### Custom Fix Logic

To customize how fixes are applied, modify `bot/auto_fix.py`:
```python
# Add custom fix logic for specific packages
if pkg_name == "your-package":
    # Your custom fix here
    pass
```

---

## 🔮 Roadmap

- [ ] **Notification Integration** - Slack/Teams alerts when PRs are created
- [ ] **HTML Reports** - Generate visual vulnerability reports
- [ ] **CVE Enrichment** - Auto-comment CVE links and details in PRs
- [ ] **Multi-Language Support** - Extend to JavaScript, Java, Go, etc.
- [ ] **Custom Fix Templates** - User-defined fix strategies
- [ ] **Scheduled Scans** - Periodic scanning independent of commits
- [ ] **Dashboard UI** - Web interface for vulnerability trends

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

- [Aqua Security](https://www.aquasec.com/) for Trivy scanner
- GitHub Actions for CI/CD platform
- PyGithub for seamless GitHub API integration

---

## 👨‍💻 Author

**Vasu Saini**

- GitHub: [@Vasu-710](https://github.com/Vasu-710)
- Project Link: [https://github.com/Vasu-710/devsecops-autofix-bot](https://github.com/Vasu-710/devsecops-autofix-bot)

---

<p align="center">Made with ❤️ by Vasu Saini</p>
<p align="center">⭐ Star this repo if you find it helpful!</p>