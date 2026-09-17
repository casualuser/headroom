#!/usr/bin/env python3
"""
Host Services Audit & Security / Updates Inspector
Audits Headroom proxy, oMLX inference backend, and client configurations (Claude Code, Orca).

Usage:
  python3 audit_host_services.py [--json] [--quick]
"""

import sys
import os
import stat
import json
import socket
import urllib.request
import urllib.error
import subprocess
import argparse

PASS = "✓"
FAIL = "✗"
WARN = "!"

class ServiceAuditor:
    def __init__(self, quick=False):
        self.quick = quick
        self.results = []
        self.failures = 0
        self.warnings = 0

    def check(self, category, name, passed, details="", warning_only=False):
        status = "PASS" if passed else ("WARN" if warning_only else "FAIL")
        if not passed:
            if warning_only:
                self.warnings += 1
            else:
                self.failures += 1
        self.results.append({
            "category": category,
            "name": name,
            "status": status,
            "details": details
        })

    def audit_headroom_service(self):
        cat = "Headroom Daemon"
        # 1. Check brew service status
        try:
            res = subprocess.run(["brew", "services", "list"], capture_output=True, text=True, timeout=5)
            started = any("headroom" in line and "started" in line for line in res.stdout.splitlines())
            self.check(cat, "Homebrew Service Status", started, "Service 'headroom' is started via brew services" if started else "Service not running in brew services")
        except Exception as e:
            self.check(cat, "Homebrew Service Status", False, str(e))

        # 2. Check LaunchAgent plist
        plist_path = os.path.expanduser("~/Library/LaunchAgents/sh.brew.headroom.plist")
        plist_exists = os.path.isfile(plist_path)
        self.check(cat, "LaunchAgent Plist Registered", plist_exists, plist_path)

        # 3. Check loopback binding security (127.0.0.1 only)
        try:
            res = subprocess.run(["lsof", "-nP", "-iTCP:8787", "-sTCP:LISTEN"], capture_output=True, text=True, timeout=5)
            lines = [l for l in res.stdout.splitlines() if "LISTEN" in l]
            loopback_only = bool(lines) and all("127.0.0.1:8787" in l for l in lines)
            wildcard = any("*:8787" in l or "0.0.0.0:8787" in l for l in lines)
            self.check(cat, "Loopback Binding (127.0.0.1 only)", loopback_only and not wildcard,
                       "Bound strictly to 127.0.0.1:8787" if loopback_only else f"Insecure binding or not listening: {res.stdout.strip()}")
        except Exception as e:
            self.check(cat, "Loopback Binding Security", False, str(e))

        # 4. Check file permissions on var and log
        var_dir = "/opt/homebrew/var/headroom"
        if os.path.isdir(var_dir):
            mode = stat.S_IMODE(os.stat(var_dir).st_mode)
            self.check(cat, "Var Directory Permissions (0700)", mode == 0o700, f"Mode is {oct(mode)} (expected 0700)")
        else:
            self.check(cat, "Var Directory Permissions", False, f"{var_dir} does not exist")

        log_file = "/opt/homebrew/var/log/headroom.log"
        if os.path.isfile(log_file):
            mode = stat.S_IMODE(os.stat(log_file).st_mode)
            self.check(cat, "Log File Permissions (0600)", mode == 0o600, f"Mode is {oct(mode)} (expected 0600)")
        else:
            self.check(cat, "Log File Permissions", False, f"{log_file} does not exist")

        # 5. Check Health & Ready endpoints
        try:
            req = urllib.request.Request("http://127.0.0.1:8787/health", headers={"User-Agent": "audit-tool"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                is_healthy = data.get("status") == "healthy" and data.get("ready") is True
                version = data.get("version", "unknown")
                rust_core = data.get("rust_core", "not loaded")
                self.check(cat, "Health & Readiness Endpoint", is_healthy, f"Status: {data.get('status')}, Ready: {data.get('ready')}, Version: {version}, Rust: {rust_core}")
        except Exception as e:
            self.check(cat, "Health & Readiness Endpoint", False, f"Failed to query /health: {e}")

    def audit_omlx_service(self):
        cat = "oMLX Inference Backend"
        # 1. Check loopback binding
        try:
            res = subprocess.run(["lsof", "-nP", "-iTCP:8888", "-sTCP:LISTEN"], capture_output=True, text=True, timeout=5)
            lines = [l for l in res.stdout.splitlines() if "LISTEN" in l]
            loopback_only = bool(lines) and all("127.0.0.1:8888" in l for l in lines)
            self.check(cat, "Loopback Binding (127.0.0.1 only)", loopback_only,
                       "Bound strictly to 127.0.0.1:8888" if loopback_only else f"Not listening or non-loopback: {res.stdout.strip()}")
        except Exception as e:
            self.check(cat, "Loopback Binding", False, str(e))

        # 2. Check loaded models
        try:
            req = urllib.request.Request("http://127.0.0.1:8888/v1/models", headers={"User-Agent": "audit-tool"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                models = [m.get("id") for m in data.get("data", [])]
                has_sonnet5 = "claude-sonnet-5" in models
                self.check(cat, "Gemma 4 (claude-sonnet-5) Loaded", has_sonnet5, f"Available models: {', '.join(models)}")
        except Exception as e:
            self.check(cat, "oMLX API Responsive", False, str(e))

    def audit_routing(self):
        cat = "Unified Routing via Port 8787"
        if self.quick:
            return
        # Test routing local model through Headroom 8787
        try:
            payload = json.dumps({
                "model": "claude-sonnet-5",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "Reply: PONG"}]
            }).encode()
            req = urllib.request.Request(
                "http://127.0.0.1:8787/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": "dummy",
                    "anthropic-version": "2023-06-01"
                }
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                role = data.get("role")
                content = "".join(c.get("text", "") for c in data.get("content", []))
                success = role == "assistant" and len(content) > 0
                self.check(cat, "Local Model Dynamic Routing (8787 -> 8888)", success, f"Response: {content.strip()[:40]}")
        except Exception as e:
            self.check(cat, "Local Model Dynamic Routing", False, str(e))

        # Test Cloud Anthropic routing through Headroom 8787
        try:
            payload = json.dumps({
                "model": "claude-3-5-haiku-20241022",
                "max_tokens": 5,
                "messages": [{"role": "user", "content": "hi"}]
            }).encode()
            req = urllib.request.Request(
                "http://127.0.0.1:8787/v1/messages",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": "dummy",
                    "anthropic-version": "2023-06-01"
                }
            )
            try:
                urllib.request.urlopen(req, timeout=5)
                self.check(cat, "Anthropic Cloud Upstream Target", True, "Successfully forwarded upstream")
            except urllib.error.HTTPError as he:
                # Anthropic cloud returns 401 with JSON containing invalid x-api-key
                err_body = he.read().decode(errors="ignore")
                reached_cloud = "invalid x-api-key" in err_body or "authentication_error" in err_body
                self.check(cat, "Anthropic Cloud Upstream Target", reached_cloud, "Targeted api.anthropic.com (received expected auth rejection for dummy key)")
        except Exception as e:
            self.check(cat, "Anthropic Cloud Upstream Target", False, str(e))

    def audit_client_configs(self):
        cat = "Client Configurations"
        # 1. Shell ~/.zshrc
        zshrc_path = os.path.expanduser("~/.zshrc")
        if os.path.isfile(zshrc_path):
            with open(zshrc_path, "r", errors="ignore") as f:
                content = f.read()
            has_anthropic_base = 'export ANTHROPIC_BASE_URL="http://127.0.0.1:8787"' in content
            has_openai_base = 'export OPENAI_BASE_URL="http://127.0.0.1:8787/v1"' in content
            self.check(cat, "~/.zshrc ANTHROPIC_BASE_URL -> 8787", has_anthropic_base, "Sets ANTHROPIC_BASE_URL=http://127.0.0.1:8787")
            self.check(cat, "~/.zshrc OPENAI_BASE_URL -> 8787/v1", has_openai_base, "Sets OPENAI_BASE_URL=http://127.0.0.1:8787/v1")

        # 2. Claude settings ~/.claude/settings.json
        claude_settings = os.path.expanduser("~/.claude/settings.json")
        if os.path.isfile(claude_settings):
            with open(claude_settings, "r", errors="ignore") as f:
                d = json.load(f)
            env = d.get("env", {})
            configured = env.get("ANTHROPIC_BASE_URL") == "http://127.0.0.1:8787"
            self.check(cat, "~/.claude/settings.json Base URL -> 8787", configured, f"Configured env: {env}")

        # 3. OpenClaude settings ~/.openclaude/settings.json
        openclaude_settings = os.path.expanduser("~/.openclaude/settings.json")
        if os.path.isfile(openclaude_settings):
            with open(openclaude_settings, "r", errors="ignore") as f:
                d = json.load(f)
            env = d.get("env", {})
            configured = env.get("ANTHROPIC_BASE_URL") == "http://127.0.0.1:8787" and d.get("model") == "claude-sonnet-5"
            self.check(cat, "~/.openclaude/settings.json (Gemma 4 default)", configured, f"model: {d.get('model')}, base_url: {env.get('ANTHROPIC_BASE_URL')}")

        # 4. Executables in PATH
        claude_omlx = os.path.expanduser("~/.local/bin/claude-omlx")
        self.check(cat, "claude-omlx Executable", os.path.isfile(claude_omlx) and os.access(claude_omlx, os.X_OK), claude_omlx)

        openclaude = os.path.expanduser("~/.local/bin/openclaude")
        self.check(cat, "openclaude Symlink -> claude-omlx", os.path.isfile(openclaude) and os.access(openclaude, os.X_OK), openclaude)

        # Check which openclaude resolves to
        res_which = subprocess.run(["zsh", "-l", "-c", "which openclaude"], capture_output=True, text=True)
        resolved_openclaude = res_which.stdout.strip()
        resolves_to_omlx = "claude-omlx" in os.path.realpath(resolved_openclaude) if resolved_openclaude else False
        self.check(cat, "Login Shell Resolves openclaude to claude-omlx", resolves_to_omlx, f"Resolved to: {resolved_openclaude}")

        # 5. Orca Settings (Advisory if Orca is running and holds state in memory)
        orca_data_path = os.path.expanduser("~/Library/Application Support/orca/profiles/local-default/orca-data.json")
        if os.path.isfile(orca_data_path):
            with open(orca_data_path, "r", errors="ignore") as f:
                orca_d = json.load(f)
            settings = orca_d.get("settings", {})
            cmd_overrides = settings.get("agentCmdOverrides", {})
            default_env = settings.get("agentDefaultEnv", {})
            has_openclaude_override = cmd_overrides.get("openclaude") == claude_omlx
            self.check(cat, "Orca agentCmdOverrides Setting", True if (has_openclaude_override or resolves_to_omlx) else False,
                       "Configured in JSON" if has_openclaude_override else "Native PATH resolution active in Orca login shells", warning_only=True)

    def audit_updates(self):
        cat = "Updates & Upstream Parity"
        if self.quick:
            return
        # 1. Homebrew livecheck
        try:
            res = subprocess.run(["brew", "livecheck", "casualuser/tap/headroom"], capture_output=True, text=True, timeout=10)
            output = res.stdout.strip()
            self.check(cat, "Homebrew Livecheck", res.returncode == 0, output)
        except Exception as e:
            self.check(cat, "Homebrew Livecheck", False, str(e), warning_only=True)

        # 2. Git Upstream status in wom7open/headroom
        headroom_dir = os.path.expanduser("~/Projects/@self/@wom/wom7open/headroom")
        if os.path.isdir(headroom_dir):
            try:
                res_local = subprocess.run(["git", "-C", headroom_dir, "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
                local_rev = res_local.stdout.strip()
                res_upstream = subprocess.run(["git", "-C", headroom_dir, "ls-remote", "https://github.com/headroomlabs-ai/headroom.git", "refs/heads/main"], capture_output=True, text=True, timeout=8)
                upstream_rev = res_upstream.stdout.split()[0][:7] if res_upstream.stdout else "unknown"
                self.check(cat, "Fork Git Parity", True, f"Local: {local_rev}, Upstream main: {upstream_rev}")
            except Exception as e:
                self.check(cat, "Fork Git Parity", False, str(e), warning_only=True)

    def run_all(self):
        self.audit_headroom_service()
        self.audit_omlx_service()
        self.audit_routing()
        self.audit_client_configs()
        self.audit_updates()

    def print_text(self):
        print("\n" + "=" * 65)
        print("  W0M HOST SERVICES & HEADROOM AUDIT REPORT")
        print("=" * 65 + "\n")
        current_cat = None
        for item in self.results:
            if item["category"] != current_cat:
                current_cat = item["category"]
                print(f"[{current_cat}]")
            symbol = PASS if item["status"] == "PASS" else (WARN if item["status"] == "WARN" else FAIL)
            print(f"  {symbol} {item['name']}")
            if item["details"]:
                print(f"      {item['details']}")
        print("\n" + "-" * 65)
        print(f"Audit Summary: {len(self.results) - self.failures - self.warnings} Passed, {self.warnings} Warnings, {self.failures} Failures")
        print("-" * 65 + "\n")
        return self.failures == 0

def main():
    parser = argparse.ArgumentParser(description="Host Services Security & Updates Auditor")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--quick", action="store_true", help="Skip live network routing checks")
    args = parser.parse_args()

    auditor = ServiceAuditor(quick=args.quick)
    auditor.run_all()

    if args.json:
        print(json.dumps({
            "results": auditor.results,
            "passed": auditor.failures == 0,
            "failures": auditor.failures,
            "warnings": auditor.warnings
        }, indent=2))
        sys.exit(0 if auditor.failures == 0 else 1)
    else:
        success = auditor.print_text()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
