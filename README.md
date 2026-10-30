# DevSecOps Auto-Fix Bot

![DevSecOps Scan](https://github.com/Vasu-710/devsecops-autofix-bot/actions/workflows/scan.yml/badge.svg)

Scans a repository's Python dependencies for known vulnerabilities and opens a
pull request that pins them to patched versions.

## What it does

On every push to `main`, and on manual trigger:

1. **Trivy** scans the repository filesystem and reports HIGH and CRITICAL
   findings as JSON.
2. **`bot/parse_trivy.py`** splits those findings into two lists by severity,
   dropping duplicates. Trivy reports per result section, so the same CVE for
   the same package can arrive more than once.
3. **`bot/auto_fix.py`** works out the highest patched version for each affected
   package, reads `requirements.txt` from the repository, rewrites the affected
   lines, commits the result to a new branch, opens a pull request, and then
   fetches that pull request back to confirm it actually contains the change.

If any step fails, the script prints the GitHub status code and message and
exits non-zero, so the workflow turns red.

Nothing is merged automatically. The output is a pull request for a person to
review.

## What it does not do

- **Only `requirements.txt` at the repository root.** No `pyproject.toml`, no
  lock files, no other languages.
- **Trivy can only resolve exact pins.** A line like `PyGithub>=1.55` has no
  single version to check, so it produces no findings. A requirements file with
  no `==` pins will scan clean no matter what is actually installed.
- **The patch may cross a major version.** The bot picks the highest patched
  version across all of a package's findings, because a lower one can leave
  other CVEs open. That can mean jumping from `1.x` to `2.x`, which may break
  the application. The bot flags this in the pull request body but does not try
  to find a compatible alternative.
- **No verification that anything still works.** It does not install the new
  versions or run the project's tests against them.

## Running it

Needs a `GH_TOKEN` repository secret with permission to write contents and open
pull requests. A fine-grained token scoped to this repository alone is enough.

Locally:

```bash
pip install PyGithub
python bot/parse_trivy.py     # expects bot/trivy-results.json
python bot/auto_fix.py        # needs GH_TOKEN and GITHUB_REPOSITORY set
```

## Tests

```bash
pip install PyGithub pytest
pytest tests/
```

33 tests. They cover the severity split and its deduplication, the version
comparison, and the requirements file rewriting, which is where every decision
about what to pin is actually made. One test runs the parser's output through
the fixer, because those two scripts only talk through a single JSON file and
nothing else checks they still agree on its shape.

The GitHub API calls are deliberately thin and are not mocked.

## Seeing it work

Trivy needs something to find. A `requirements.txt` with nothing vulnerable in
it means no findings, an early exit, and a green run with no pull request,
which looks identical to the eleven months this thing was broken.

To watch it work, give it a target:

```bash
echo "PyYAML==5.3.1" >> requirements.txt
git commit -am "Reintroduce a vulnerable pin" && git push
```

The scan runs on push. A pull request should appear within a minute or two. If
one does not, that is a real failure now and the run goes red, which is the
whole point of the rewrite described below.

Anything pinned in `requirements.txt` is the bot's test subject, not its
dependency list. The workflow installs what it actually needs with
`pip install PyGithub pytest`, so a deliberately broken pin in there cannot
stop the run.

## History

From November 2025 until October 2026 this bot never opened a single pull
request, and every run reported success.

It edited `requirements.txt` on the Actions runner and never committed the
change, so the branch it created stayed identical to `main`. GitHub rejects a
pull request between two identical branches, a bare `except:` caught the
rejection and printed `"Pull request already exists or failed."`, and the script
exited zero. Green tick, nothing done.

It was also dormant for a second reason. `requirements.txt` held one unpinned
dependency, Trivy had nothing it could resolve, the scan returned no findings,
and the script exited before it ever reached the pull request code.

Both were found by looking at the repository rather than at the source: the pull
request tab showed zero pull requests ever, and the branch list showed one
branch. Nothing here deletes branches, so if the bot had ever got as far as
creating one, it would still be there.

`bot/parse_trivy.py` was a third gap, found later and quietly. It had no tests
at all, no handling for a missing or malformed scan file, and it counted a
finding once per result section rather than once per finding. A missing
`trivy-results.json` would have crashed it with a traceback, which is at least
loud. Double counting would not have been.
