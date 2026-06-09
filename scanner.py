#!/usr/bin/env python3
"""
Miasma / Phantom Gyp supply chain attack scanner.
Detects TeamPCP campaign persistence and IOCs on a developer machine.

Campaign summary:
  - Wave 1 (Miasma): 32 @redhat-cloud-services npm packages, ~117k weekly DLs
  - Wave 2 (Phantom Gyp): 57 more packages, ~647k monthly DLs, binding.gyp bypass
  - Persistence: ~/.claude/settings.json hooks, .vscode/tasks.json auto-tasks
  - Exfil: AWS/GCP/Azure/k8s/SSH/GitHub/npm credentials
  - Wiper: triggered on credential rotation to destroy home dir

References:
  https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/
  https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm
  https://snyk.io/blog/miasma-supply-chain-attack-malicious-code-redhat-cloud-services-npm-packages/
"""

import json
import os
import re
import sys
import subprocess
from pathlib import Path
from typing import Iterable, Optional

# ── ANSI colors ─────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{RESET}"

# ── Known affected packages (wave 1 + wave 2) ───────────────────────────────
# Wave 1: 32 packages published June 1, 2026 under @redhat-cloud-services
# Wave 2: 57 packages, binding.gyp technique
# Source: Microsoft TI / StepSecurity reports
MIASMA_PACKAGES_W1 = {
    "@redhat-cloud-services/frontend-components",
    "@redhat-cloud-services/frontend-components-utilities",
    "@redhat-cloud-services/frontend-components-notifications",
    "@redhat-cloud-services/rbac-client",
    "@redhat-cloud-services/insights-common-typescript",
    "@redhat-cloud-services/api-clients-common",
    "@redhat-cloud-services/host-inventory-client",
    "@redhat-cloud-services/policies-client",
    "@redhat-cloud-services/vulnerabilities-client",
    "@redhat-cloud-services/patch-client",
    "@redhat-cloud-services/advisor-client",
    "@redhat-cloud-services/drift-client",
    "@redhat-cloud-services/compliance-client",
    "@redhat-cloud-services/remediations-client",
    "@redhat-cloud-services/sources-client",
    "@redhat-cloud-services/cost-management-client",
    "@redhat-cloud-services/sources-api-components",
    "@redhat-cloud-services/frontend-components-config",
    "@redhat-cloud-services/tsc-transform-imports",
    "@redhat-cloud-services/types-common",
    "@redhat-cloud-services/chrome-service-client",
    "@redhat-cloud-services/frontend-components-pdf-generator",
    "@redhat-cloud-services/entitlements-client",
    "@redhat-cloud-services/inventory-client",
    "@redhat-cloud-services/user-access-client",
    "@redhat-cloud-services/export-service-client",
    "@redhat-cloud-services/image-builder-client",
    "@redhat-cloud-services/ros-client",
    "@redhat-cloud-services/tasks-client",
    "@redhat-cloud-services/edge-frontend-components",
    "@redhat-cloud-services/registration-assistant-client",
    "@redhat-cloud-services/logging-client",
}

# Poisoned version ranges: versions published ~2026-06-01 are suspect.
# Exact poisoned version list would come from the npm advisory; flag all
# installed versions and let user cross-reference with the advisory.
POISONED_WAVE1_DATE = "2026-06-01"

SUSPICIOUS_INDICATORS = [
    # Exfil / outbound execution
    {"pattern": r"curl\s+['\"]?https?://(?!localhost|127\.0\.0\.1)", "label": "outbound curl", "score": 3},
    {"pattern": r"wget\s+['\"]?https?://(?!localhost|127\.0\.0\.1)", "label": "outbound wget", "score": 3},
    {"pattern": r"fetch\s*\(\s*['\"]https?://(?!localhost)", "label": "outbound fetch", "score": 3},
    {"pattern": r"https?://[a-z0-9\-]+\.[a-z]{2,}[^\s'\";]*(?:token|secret|key|cred)", "label": "credential URL", "score": 4},

    # Execution / obfuscation
    {"pattern": r"base64\s*-d", "label": "base64 decode pipe", "score": 2},
    {"pattern": r"echo\s+[A-Za-z0-9+/]{20,}={0,2}\s*\|", "label": "base64-like pipe", "score": 2},
    {"pattern": r"\beval\s*\(", "label": "eval call", "score": 2},
    {"pattern": r"\bexec\s*\(", "label": "exec call", "score": 2},
    {"pattern": r"python\s+-c\s+['\"]", "label": "inline python exec", "score": 2},
    {"pattern": r"node\s+-e\s+['\"]", "label": "inline node exec", "score": 2},
    {"pattern": r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}", "label": "hex-encoded payload", "score": 3},

    # Credential harvesting
    {"pattern": r"\.aws[/\\]credentials", "label": "AWS credential access", "score": 3},
    {"pattern": r"\.kube[/\\]config", "label": "kubeconfig access", "score": 3},
    {"pattern": r"\.npmrc", "label": ".npmrc access", "score": 2},
    {"pattern": r"id_rsa|id_ed25519|id_ecdsa", "label": "SSH key access", "score": 3},
    {"pattern": r"gh/hosts\.yml|github.*token|npm.*_authToken", "label": "developer token access", "score": 3},

    # Destructive behavior
    {"pattern": r"rm\s+-rf\s+\$HOME|\brm\s+-rf\s+~/", "label": "home dir wipe command", "score": 5},
    {"pattern": r"find\s+\$HOME.*-exec\s+shred", "label": "shred home command", "score": 5},

    # TeamPCP-style persistence / remote access
    {"pattern": r"ngrok|serveo\.net|pagekite", "label": "tunnel service", "score": 4},
    {"pattern": r"ssh\s+-R\s+\d+:", "label": "reverse SSH tunnel", "score": 4},
    {"pattern": r"nc\s+-[el].*\d{4,5}", "label": "netcat listener", "score": 4},
]

COMPILED_INDICATORS = [
    (re.compile(indicator["pattern"], re.IGNORECASE), indicator["label"], indicator["score"])
    for indicator in SUSPICIOUS_INDICATORS
]

SAFE_TASK_COMMAND_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"^(npm|pnpm|yarn)\s+(install|run|test|build|lint|typecheck)\b",
        r"^(make|just|cargo|go|python|python3|pytest|tox)\b",
        r"^(eslint|prettier|tsc|vite|webpack)\b",
    )
]

SAFE_HOOK_COMMAND_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"^(jq|python3?|node)\b",
        r"^(echo|printf|true|false)\b",
        r"^(git)\s+(status|diff|rev-parse|branch)\b",
    )
]

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".npm",
    ".pnpm-store",
    ".yarn",
    ".venv",
    "venv",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".turbo",
    "__pycache__",
}
MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_EXCLUDED_PATH_PARTS = {
    "tests",
    "test",
    "__tests__",
    "fixtures",
    "corpus",
    "demo",
    "demos",
    "examples",
    "sample",
    "samples",
}
COMMON_BENIGN_PROCESS_PATTERNS = [
    re.compile(r"/proc/self/exe\b.*--type=utility\b", re.IGNORECASE),
    re.compile(r"\b(chromium|chrome|google-chrome|code|cursor|windsurf|vscodium)\b", re.IGNORECASE),
]


def scan_text(text: str) -> list[tuple[str, str, int]]:
    """Return list of (label, matched_snippet, score) for each suspicious indicator."""
    hits = []
    for regex, label, score in COMPILED_INDICATORS:
        m = regex.search(text)
        if m:
            start = max(0, m.start() - 20)
            end   = min(len(text), m.end() + 40)
            snippet = text[start:end].replace("\n", " ").strip()
            hits.append((label, snippet, score))
    return hits


def is_probably_safe_command(command: str, safe_patterns: list[re.Pattern[str]]) -> bool:
    compact = summarize_command(command)
    return any(pattern.search(compact) for pattern in safe_patterns)


def score_hits(hits: list[tuple[str, str, int]]) -> tuple[int, list[str]]:
    total = 0
    labels: list[str] = []
    for label, _snippet, score in hits:
        total += score
        labels.append(label)
    return total, labels


def classify_hits(hits: list[tuple[str, str, int]], *, autorun: bool = False) -> Optional[str]:
    if not hits:
        return None
    total, _labels = score_hits(hits)
    if any(score >= 5 for _label, _snippet, score in hits):
        return "CRITICAL"
    if autorun and total >= 4:
        return "CRITICAL"
    if total >= 6:
        return "HIGH"
    if total >= 3:
        return "MEDIUM"
    return None


def describe_hits(hits: list[tuple[str, str, int]]) -> str:
    labels = sorted({label for label, _snippet, _score in hits})
    return ", ".join(labels)


def safe_read_text(path: Path, *, max_bytes: int = MAX_TEXT_FILE_BYTES) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            finding(
                "INFO",
                "scan_limit",
                str(path),
                f"Skipped oversized file (> {max_bytes} bytes)",
            )
            return None
        return path.read_text(errors="replace")
    except OSError:
        return None


def safe_read_bytes(path: Path, *, max_bytes: int = MAX_TEXT_FILE_BYTES) -> Optional[bytes]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_bytes()
    except OSError:
        return None


def strip_json_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    in_string = False
    escape = False
    while i < len(text):
        ch = text[i]
        if in_string:
            result.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "/":
                i += 2
                while i < len(text) and text[i] not in "\r\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < len(text) and text[i:i + 2] != "*/":
                    i += 1
                i += 2
                continue
        result.append(ch)
        i += 1
    return "".join(result)


def strip_trailing_commas(text: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", text)


def load_jsonc(text: str):
    return json.loads(strip_trailing_commas(strip_json_comments(text)))


def should_skip_path(path: Path, *, include_test_paths: bool) -> bool:
    if include_test_paths:
        return False
    lowered_parts = {part.lower() for part in path.parts}
    return bool(lowered_parts & DEFAULT_EXCLUDED_PATH_PARTS)


def iter_candidate_files(roots: list[Path], filename: str, *, include_test_paths: bool) -> Iterable[Path]:
    seen: set[Path] = set()
    for root in roots:
        for current_root, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if dirname not in SKIP_DIRS and not dirname.startswith(".pytest_cache")
            ]
            current_path = Path(current_root)
            dirnames[:] = [
                dirname
                for dirname in dirnames
                if not should_skip_path(current_path / dirname, include_test_paths=include_test_paths)
            ]
            if filename not in filenames:
                continue
            candidate = current_path / filename
            if should_skip_path(candidate, include_test_paths=include_test_paths):
                continue
            try:
                resolved = candidate.resolve()
            except OSError:
                resolved = candidate
            if resolved in seen:
                continue
            seen.add(resolved)
            yield candidate


def summarize_command(command: str, limit: int = 140) -> str:
    compact = " ".join(command.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def read_cmdline_for_pid(pid: str) -> Optional[str]:
    cmdline_path = Path("/proc") / pid / "cmdline"
    raw = safe_read_bytes(cmdline_path, max_bytes=64 * 1024)
    if raw is None:
        return None
    parts = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
    if not parts:
        return None
    return " ".join(parts)


def is_benign_process_command(command: str) -> bool:
    compact = summarize_command(command, limit=500)
    return any(pattern.search(compact) for pattern in COMMON_BENIGN_PROCESS_PATTERNS)


# ── Findings collector ───────────────────────────────────────────────────────
findings: list[dict] = []
_finding_keys: set[tuple[str, str, str, str, str]] = set()

def finding(severity: str, category: str, path: str, detail: str, snippet: str = ""):
    key = (severity, category, path, detail, snippet)
    if key in _finding_keys:
        return
    _finding_keys.add(key)
    findings.append({
        "severity": severity,   # CRITICAL / HIGH / MEDIUM / INFO
        "category": category,
        "path":     path,
        "detail":   detail,
        "snippet":  snippet,
    })


def clear_findings():
    findings.clear()
    _finding_keys.clear()


# ── Check 1: ~/.claude/settings.json ────────────────────────────────────────
def check_claude_settings():
    settings_path = Path.home() / ".claude" / "settings.json"
    if not settings_path.exists():
        return

    try:
        raw_text = safe_read_text(settings_path)
        if raw_text is None:
            return
        data = load_jsonc(raw_text)
    except json.JSONDecodeError as e:
        finding("HIGH", "claude_settings", str(settings_path),
                f"JSON parse error — file may be corrupted/tampered: {e}")
        return

    hooks = data.get("hooks", {})
    if not hooks:
        return

    # Legitimate hook types defined by Claude Code
    LEGIT_HOOK_TYPES = {
        "PreToolUse", "PostToolUse", "UserPromptSubmit",
        "Stop", "Notification", "SubagentStop", "SessionStart",
    }
    AUTO_HOOK_TYPES = {"SessionStart"}

    for hook_type, hook_list in hooks.items():
        if hook_type not in LEGIT_HOOK_TYPES:
            finding("HIGH", "claude_settings", str(settings_path),
                    f"Unknown hook type '{hook_type}' — Miasma plants custom hook names")

        if not isinstance(hook_list, list):
            hook_list = [hook_list]

        for entry in hook_list:
            # hook can be a string or {matcher, hooks: [{command}]}
            commands_to_check = []
            if isinstance(entry, str):
                commands_to_check.append(entry)
            elif isinstance(entry, dict):
                for h in entry.get("hooks", []):
                    if isinstance(h, dict):
                        commands_to_check.append(h.get("command", ""))
                    elif isinstance(h, str):
                        commands_to_check.append(h)

            for cmd in commands_to_check:
                if not cmd:
                    continue
                hits = scan_text(cmd)
                severity = classify_hits(hits, autorun=hook_type in AUTO_HOOK_TYPES)
                if severity:
                    finding(
                        severity,
                        "claude_settings",
                        str(settings_path),
                        f"Suspicious pattern(s) in {hook_type} hook: {describe_hits(hits)}",
                        summarize_command(cmd),
                    )
                elif hook_type in AUTO_HOOK_TYPES and not is_probably_safe_command(cmd, SAFE_HOOK_COMMAND_PATTERNS):
                    finding(
                        "MEDIUM",
                        "claude_settings",
                        str(settings_path),
                        f"Auto-run {hook_type} hook executes an unusual command; verify legitimacy",
                        summarize_command(cmd),
                    )


# ── Check 2: .vscode/tasks.json ─────────────────────────────────────────────
def check_vscode_tasks(search_roots: list[Path], *, include_test_paths: bool):
    task_files = list(iter_candidate_files(search_roots, "tasks.json", include_test_paths=include_test_paths))
    task_files = [path for path in task_files if path.parent.name == ".vscode"]

    # Also check home-level vscode config
    home_tasks = Path.home() / ".vscode" / "tasks.json"
    if home_tasks.exists():
        task_files.append(home_tasks)

    for task_path in task_files:
        try:
            raw_text = safe_read_text(task_path)
            if raw_text is None:
                continue
            data = load_jsonc(raw_text)
        except json.JSONDecodeError:
            hits = scan_text(raw_text)
            severity = classify_hits(hits)
            if severity:
                finding(
                    severity,
                    "vscode_tasks",
                    str(task_path),
                    f"Task file could not be parsed and contains suspicious pattern(s): {describe_hits(hits)}",
                    summarize_command(raw_text[:220]),
                )
            continue

        tasks = data.get("tasks", [])
        for task in tasks:
            run_on = (task.get("runOptions") or {}).get("runOn", "")
            cmd    = task.get("command", "")
            args   = " ".join(str(a) for a in task.get("args", []))
            options = task.get("options") or {}
            env = options.get("env") or {}
            env_text = " ".join(f"{key}={value}" for key, value in env.items())
            full = f"{cmd} {args} {env_text}".strip()

            # folderOpen = auto-executes on project open — primary Miasma vector
            if run_on == "folderOpen":
                hits = scan_text(full)
                severity = classify_hits(hits, autorun=True)
                if severity:
                    finding(
                        severity,
                        "vscode_tasks",
                        str(task_path),
                        f"Auto-run task (folderOpen) with suspicious pattern(s): {describe_hits(hits)}",
                        summarize_command(full),
                    )
                elif not is_probably_safe_command(full, SAFE_TASK_COMMAND_PATTERNS):
                    finding("HIGH", "vscode_tasks", str(task_path),
                            f"Auto-run task (folderOpen): '{task.get('label', 'unlabeled')}' — "
                            "verify this task is legitimate",
                            summarize_command(full))
            else:
                hits = scan_text(full)
                severity = classify_hits(hits)
                if severity:
                    finding(
                        severity,
                        "vscode_tasks",
                        str(task_path),
                        f"Suspicious pattern(s) in task '{task.get('label', 'unlabeled')}': {describe_hits(hits)}",
                        summarize_command(full),
                    )


# ── Check 3: npm packages ────────────────────────────────────────────────────
def check_npm_packages(search_roots: list[Path], *, include_test_paths: bool):
    """Scan package-lock.json, yarn.lock, pnpm-lock.yaml, and node_modules."""

    def scan_lockfile_text(text: str, lock_path: Path):
        for pkg in MIASMA_PACKAGES_W1:
            for match in re.finditer(re.escape(pkg), text):
                ctx = text[match.start():match.start() + 220].replace("\n", " ")
                version_match = re.search(r"\bversion\b[^0-9]*([0-9][^,'\"\s}]*)", ctx)
                detail = f"Miasma wave-1 package found in lockfile: {pkg}"
                if version_match:
                    detail += f" @ {version_match.group(1)}"
                finding("CRITICAL", "npm_package", str(lock_path), detail, ctx[:140])
                break

    def scan_package_lock(lock_path: Path):
        raw_text = safe_read_text(lock_path)
        if raw_text is None:
            return

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            scan_lockfile_text(raw_text, lock_path)
            return

        seen = set()

        def emit(pkg: str, version: str = ""):
            if pkg in seen:
                return
            seen.add(pkg)
            detail = f"Miasma wave-1 package found in lockfile: {pkg}"
            if version:
                detail += f" @ {version}"
            finding("CRITICAL", "npm_package", str(lock_path), detail)

        for pkg_name, meta in (data.get("dependencies") or {}).items():
            if pkg_name in MIASMA_PACKAGES_W1:
                emit(pkg_name, str((meta or {}).get("version", "")))

        for pkg_name, meta in (data.get("packages") or {}).items():
            name = pkg_name.removeprefix("node_modules/")
            if name in MIASMA_PACKAGES_W1:
                emit(name, str((meta or {}).get("version", "")))

    for root in search_roots:
        # package-lock.json
        for lock_path in iter_candidate_files([root], "package-lock.json", include_test_paths=include_test_paths):
            if "node_modules" in lock_path.parts:
                continue
            scan_package_lock(lock_path)

        # yarn.lock
        for lock_path in iter_candidate_files([root], "yarn.lock", include_test_paths=include_test_paths):
            if "node_modules" in lock_path.parts:
                continue
            text = safe_read_text(lock_path)
            if text is not None:
                scan_lockfile_text(text, lock_path)

        # pnpm-lock.yaml
        for lock_path in iter_candidate_files([root], "pnpm-lock.yaml", include_test_paths=include_test_paths):
            if "node_modules" in lock_path.parts:
                continue
            text = safe_read_text(lock_path)
            if text is not None:
                scan_lockfile_text(text, lock_path)

        # node_modules direct presence
        for pkg in MIASMA_PACKAGES_W1:
            scope, name = pkg.split("/")
            mod_path = root / "node_modules" / scope / name
            if mod_path.exists():
                detail = f"Miasma wave-1 package installed: {pkg}"
                # Also check its postinstall script for live payload
                pkg_json = mod_path / "package.json"
                if pkg_json.exists():
                    try:
                        raw_text = safe_read_text(pkg_json)
                        if raw_text is None:
                            continue
                        pdata = load_jsonc(raw_text)
                        version = pdata.get("version", "")
                        if version:
                            detail += f" @ {version}"
                        finding("CRITICAL", "npm_package", str(mod_path), detail)
                        scripts = pdata.get("scripts", {})
                        for script_name in ("postinstall", "install", "preinstall"):
                            if script_name in scripts:
                                hits = scan_text(scripts[script_name])
                                severity = classify_hits(hits)
                                if severity:
                                    finding(
                                        severity,
                                        "npm_package",
                                        str(pkg_json),
                                        f"Suspicious {script_name} script: {describe_hits(hits)}",
                                        summarize_command(scripts[script_name]),
                                    )
                    except json.JSONDecodeError:
                        pass
                else:
                    finding("CRITICAL", "npm_package", str(mod_path), detail)


# ── Check 4: binding.gyp files (Phantom Gyp wave 2) ─────────────────────────
def check_binding_gyp(search_roots: list[Path], *, include_test_paths: bool):
    for gyp_path in iter_candidate_files(search_roots, "binding.gyp", include_test_paths=include_test_paths):
        text = safe_read_text(gyp_path)
        if text is None:
            continue

        # binding.gyp is JSON-ish (allows comments); just scan text
        hits = scan_text(text)
        severity = classify_hits(hits)
        if severity:
            finding(
                severity,
                "binding_gyp",
                str(gyp_path),
                f"Phantom Gyp suspicious pattern(s): {describe_hits(hits)}",
                summarize_command(text[:220]),
            )
            continue

        # Also flag gyp files that define action steps with shell commands.
        if re.search(r'"action"\s*:\s*\[', text):
            action_m = re.search(r'"action"\s*:\s*\[([^\]]+)\]', text)
            if action_m:
                action_text = action_m.group(1)
                if re.search(r'curl|wget|powershell|cmd\.exe|bash\s+-c|sh\s+-c|python\s+-c|node\s+-e', action_text, re.I):
                    finding("HIGH", "binding_gyp", str(gyp_path),
                            "binding.gyp defines shell action — verify legitimacy",
                            summarize_command(action_text))


# ── Check 5: Credential file exposure inventory ──────────────────────────────
def check_credential_files():
    cred_files = [
        ("~/.aws/credentials",          "AWS credentials"),
        ("~/.aws/config",               "AWS config"),
        ("~/.kube/config",              "Kubernetes config"),
        ("~/.npmrc",                    "npm auth token"),
        ("~/.ssh/id_rsa",               "SSH private key (RSA)"),
        ("~/.ssh/id_ed25519",           "SSH private key (Ed25519)"),
        ("~/.ssh/id_ecdsa",             "SSH private key (ECDSA)"),
        ("~/.config/gcloud/credentials.db", "GCloud credentials"),
        ("~/.config/gh/hosts.yml",      "GitHub CLI token"),
        ("~/.docker/config.json",       "Docker registry credentials"),
        ("~/.azure/msal_token_cache.bin", "Azure token cache"),
    ]

    present = []
    for path_str, label in cred_files:
        p = Path(path_str).expanduser()
        if p.exists():
            size = p.stat().st_size
            present.append((str(p), label, size))

    return present


# ── Check 6: Active suspicious processes ────────────────────────────────────
def check_processes():
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.splitlines()
    except (subprocess.SubprocessError, FileNotFoundError):
        return

    suspicious_proc_patterns = [
        (re.compile(r"ngrok", re.IGNORECASE), "ngrok tunnel (TeamPCP C2 technique)"),
        (re.compile(r"serveo", re.IGNORECASE), "serveo tunnel"),
        (re.compile(r"ssh.*-R\s+\d+", re.IGNORECASE), "reverse SSH tunnel"),
        (re.compile(r"nc\s+-[el]", re.IGNORECASE), "netcat listener"),
        (re.compile(r"python.*-c.*(exec|base64|urllib|requests)", re.IGNORECASE), "inline python exec"),
        (re.compile(r"node.*-e.*(fetch|http|https|child_process)", re.IGNORECASE), "inline node exec"),
    ]

    for line in lines:
        pid_parts = line.split(maxsplit=10)
        pid = pid_parts[1] if len(pid_parts) > 1 else "?"
        if pid == "PID" or not pid.isdigit():
            continue
        command = read_cmdline_for_pid(pid) or (pid_parts[10] if len(pid_parts) > 10 else line)
        if is_benign_process_command(command):
            continue
        for regex, label in suspicious_proc_patterns:
            match = regex.search(command)
            if match:
                snippet = summarize_command(command[max(0, match.start() - 30):match.end() + 90], limit=180)
                finding(
                    "HIGH",
                    "process",
                    f"PID {pid}",
                    f"Suspicious process: {label}",
                    snippet,
                )
                break


# ── Check 7: npm publish token scope (worm self-propagation check) ───────────
def check_npm_token_scope():
    npmrc = Path.home() / ".npmrc"
    if not npmrc.exists():
        return

    text = safe_read_text(npmrc)
    if text is None:
        return
    # Check if token is stored (worm uses stolen tokens to publish new versions)
    if re.search(r"//registry\.npmjs\.org/:_authToken\s*=\s*\S+", text):
        finding("HIGH", "npm_token", str(npmrc),
                "npm publish token stored in .npmrc — Miasma worm uses this to self-propagate. "
                "Rotate this token immediately if machine may be compromised.")


def add_exposure_summary(present_creds: list[tuple[str, str, int]]):
    if not present_creds:
        return
    labels = "; ".join(label for _, label, _ in present_creds)
    finding(
        "INFO",
        "exposure",
        "local machine",
        f"{len(present_creds)} credential stores present that would be high-value on a compromised host",
        labels,
    )


def run_scan(roots: list[Path], *, include_processes: bool = True, include_test_paths: bool = False):
    clear_findings()
    check_claude_settings()
    check_vscode_tasks(roots, include_test_paths=include_test_paths)
    check_npm_packages(roots, include_test_paths=include_test_paths)
    check_binding_gyp(roots, include_test_paths=include_test_paths)
    present_creds = check_credential_files()
    check_npm_token_scope()
    if include_processes:
        check_processes()
    add_exposure_summary(present_creds)
    return list(findings)


# ── Report ───────────────────────────────────────────────────────────────────
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
SEV_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "INFO":     CYAN,
}

def print_report():
    sorted_findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 99))

    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print()
    print(color("=" * 70, BOLD))
    print(color("  Miasma / Phantom Gyp Scanner — TeamPCP Campaign", BOLD))
    print(color("=" * 70, BOLD))
    print()

    if not findings:
        print(color("  No indicators found.", GREEN))
        print()
        print("  Note: absence of findings does not confirm clean. If you installed")
        print("  any @redhat-cloud-services package between 2026-05-28 and 2026-06-05,")
        print("  cross-check with the npm advisory and manually inspect:")
        print("    ~/.claude/settings.json")
        print("    Any .vscode/tasks.json in your projects")
        print()
        return

    for f in sorted_findings:
        sev_str = color(f"[{f['severity']:8}]", SEV_COLOR.get(f["severity"], ""))
        print(f"  {sev_str}  {color(f['category'], BOLD)}")
        print(f"             Path   : {f['path']}")
        print(f"             Detail : {f['detail']}")
        if f["snippet"]:
            print(f"             Match  : {color(repr(f['snippet'][:100]), YELLOW)}")
        print()

    print(color("─" * 70, BOLD))
    print(f"  Summary: "
          f"{color(str(counts['CRITICAL']), SEV_COLOR['CRITICAL'])} critical  "
          f"{color(str(counts['HIGH']), SEV_COLOR['HIGH'])} high  "
          f"{color(str(counts['MEDIUM']), SEV_COLOR['MEDIUM'])} medium  "
          f"{color(str(counts['INFO']), SEV_COLOR['INFO'])} info")
    print()

    if counts["CRITICAL"] > 0:
        print(color("  !! CRITICAL findings detected.", RED + BOLD))
        print()
        print("  NEXT STEPS (perform in this order — do NOT revoke tokens first):")
        print()
        print("  1. Disconnect machine from network BEFORE revoking any credentials.")
        print("     Miasma wiper triggers on token revocation while malware is active.")
        print()
        print("  2. Remove persistence:")
        print("       ~/.claude/settings.json   — remove injected hooks, or delete and")
        print("                                   re-run 'claude' to regenerate defaults")
        print("       .vscode/tasks.json        — remove folderOpen auto-tasks")
        print()
        print("  3. Uninstall affected packages:")
        print("       npm uninstall @redhat-cloud-services/<name>")
        print()
        print("  4. Rotate ALL credentials found in credential inventory above.")
        print("     Priority order: npm token, GitHub token, AWS, GCloud, Azure, SSH keys")
        print()
        print("  5. Check your npm packages for unauthorized publishes (worm propagation):")
        print("       npm access list packages <your-npm-username>")
        print()
        print("  6. Report to: security@redhat.com + npm security (npmjs.com/support)")
        print()
        print("  Cleanup reference: https://snyk.io/blog/miasma-supply-chain-attack-"
              "malicious-code-redhat-cloud-services-npm-packages/")
        print()


def print_json_report():
    counts = {s: 0 for s in SEV_ORDER}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1

    payload = {
        "findings": sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 99)),
        "summary": counts,
    }
    print(json.dumps(payload, indent=2))


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan for Miasma / Phantom Gyp (TeamPCP) campaign IOCs"
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the scanner",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=[str(Path.home()), str(Path.cwd())],
        help="Directories to scan when using --run (default: HOME + cwd)",
    )
    parser.add_argument(
        "--no-processes",
        action="store_true",
        help="Skip live process scan",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Include test/demo/fixture directories in the scan",
    )
    args = parser.parse_args()

    if not args.run:
        parser.print_help()
        sys.exit(0)

    search_roots = [Path(p) for p in args.paths]
    # Deduplicate, keep only existing dirs
    seen = set()
    roots = []
    for r in search_roots:
        r = r.resolve()
        if r not in seen and r.exists():
            seen.add(r)
            roots.append(r)

    if not args.json:
        print(f"\nScanning: {', '.join(str(r) for r in roots)}")
        print("Checks: claude_settings, vscode_tasks, npm_packages, binding_gyp, "
              "credential_inventory, processes, npm_token\n")

    run_scan(
        roots,
        include_processes=not args.no_processes,
        include_test_paths=args.test,
    )

    if args.json:
        print_json_report()
    else:
        print_report()

    # Exit code: 2=critical, 1=high/medium, 0=clean
    if any(f["severity"] == "CRITICAL" for f in findings):
        sys.exit(2)
    if any(f["severity"] in ("HIGH", "MEDIUM") for f in findings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
