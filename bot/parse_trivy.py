import json
import os

# Path to Trivy output JSON
trivy_file = os.path.join(os.path.dirname(__file__), "trivy-results.json")

# Load Trivy results
with open(trivy_file) as f:
    data = json.load(f)

high_issues = []
critical_issues = []

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        severity = vuln.get("Severity", "")
        if severity == "HIGH":
            high_issues.append(vuln)
        elif severity == "CRITICAL":
            critical_issues.append(vuln)

print(f"HIGH vulnerabilities: {len(high_issues)}")
print(f"CRITICAL vulnerabilities: {len(critical_issues)}")

# Save parsed JSON
parsed_file = os.path.join(os.path.dirname(__file__), "trivy-parsed.json")
with open(parsed_file, "w") as f:
    json.dump({
        "HIGH": high_issues,
        "CRITICAL": critical_issues
    }, f, indent=2)

print("Trivy results parsed ✅")
