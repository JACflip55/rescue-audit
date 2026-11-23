# rescue-audit

A quick health check for codebases that were built in a hurry. Doesn't burn your tokens!

Point it at a project and it lists the problems that most often bite a
fast-built MVP once real users arrive. It is a first pass, not a full review:
one file, standard library only, runs in a second or two.

```
$ python rescue_audit.py ~/code/my-app
rescue-audit: 5 findings in /Users/me/code/my-app

HIGH (2)
  [no-tests] No automated tests found
  [secret] Possible hardcoded credential in source  api/db.py:14

MEDIUM (2)
  [no-ci] No CI configuration found; nothing runs checks before a deploy
  [unpinned-deps] 7 dependencies without an exact version (e.g. requests)  requirements.txt

LOW (1)
  [no-readme] No README; setup steps live in someone's head
```

## What it checks

| Check | Severity | What it looks for |
|---|---|---|
| `secret` | high | AWS access keys, private keys, `sk-` style API keys, hardcoded passwords and tokens |
| `env-file` | high | `.env` files sitting in the project tree |
| `no-tests` | high | no test files anywhere |
| `no-ci` | medium | no GitHub Actions, GitLab CI, CircleCI, Jenkins, Azure, Bitbucket or Buildkite config |
| `unpinned-deps` | medium | `requirements.txt` entries without an exact version |
| `no-lockfile` | medium | `package.json`, `Pipfile` or `Gemfile` with no lockfile beside it |
| `debug` | medium | `DEBUG = True` / `debug=True` left in code |
| `swallowed-error` | medium | bare `except:`, `except Exception: pass`, empty `catch {}` |
| `long-file` | low | source files over 800 lines |
| `todo-debt` | low | 20 or more TODO/FIXME markers |
| `no-readme`, `no-gitignore` | low | missing basics |

Dependency folders, build output and minified bundles are skipped.

## Usage

Requires Python 3.9 or newer. No install step.

```
python rescue_audit.py [path]            # human-readable report
python rescue_audit.py [path] --json     # machine-readable findings
python rescue_audit.py [path] --strict   # exit 1 if any high-severity finding
```

## Limits

The checks are pattern matches. Expect some false positives (a long random
string that is not a secret) and false negatives (a secret in an unusual
format). A clean report means the obvious problems are absent, not that the
code is production-ready.

## Tests

```
python -m unittest discover -s tests
```

## License

MIT
