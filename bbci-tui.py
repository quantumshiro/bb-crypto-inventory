#!/usr/bin/env python3
"""bbci TUI — Interactive blackbox crypto inventory harness.

A terminal UI for running bbci tools step-by-step, choosing which
LLM CLI to analyze results with (claude, codex, openclaw), and
evaluating each step independently.

Usage:
    uv run --with httpx,pyyaml python bbci-tui.py
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ─── State ────────────────────────────────────────────────────

SESSION_DIR = Path("sessions")
RESULTS_DIR = Path("results")

state = {
    "target": "",
    "host": "",
    "port": 443,
    "llm_cmd": "claude",  # claude | codex | openclaw
    "findings": [],
    "phase_results": {},
    "session_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
}

LLM_OPTIONS = {
    "1": ("claude", "Claude Code CLI"),
    "2": ("codex", "OpenAI Codex CLI"),
    "3": ("openclaw", "OpenClaw CLI"),
}

# ─── Helpers ──────────────────────────────────────────────────

def clear():
    os.system("clear" if os.name != "nt" else "cls")


def header():
    print("╔══════════════════════════════════════════════════════╗")
    print("║  🔐 bbci — Blackbox Crypto Inventory TUI            ║")
    print("╚══════════════════════════════════════════════════════╝")
    if state["target"]:
        print(f"  Target: {state['target']}")
        print(f"  LLM:    {state['llm_cmd']}")
        print(f"  Session: {state['session_id']}")
    print()


def save_result(phase: str, tool: str, result: dict):
    """Save tool result to session directory."""
    session_dir = SESSION_DIR / state["session_id"]
    session_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{phase}_{tool}_{int(time.time())}.json"
    path = session_dir / filename
    path.write_text(json.dumps(result, indent=2, default=str))
    print(f"  📁 Saved: {path}")
    return path


def run_tool(phase: str, tool_cmd: list[str]) -> dict | None:
    """Run a Python tool and capture output."""
    full_cmd = ["uv", "run", "--with", "httpx", "python"] + tool_cmd
    print(f"\n  ⚡ Running: {' '.join(full_cmd)}")
    print("  " + "─" * 50)

    start = time.monotonic()
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
        elapsed = time.monotonic() - start

        if result.returncode != 0:
            print(f"  ❌ Error (rc={result.returncode}):")
            print(f"  {result.stderr[:500]}")
            return None

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            data = {"raw_output": result.stdout[:3000]}

        data["_meta"] = {
            "tool_cmd": tool_cmd,
            "duration_seconds": round(elapsed, 2),
            "timestamp": datetime.now().isoformat(),
        }

        # Print summary
        print(f"  ✅ Done in {elapsed:.1f}s")
        # Print first 30 lines of output
        lines = result.stdout.strip().split("\n")
        for line in lines[:30]:
            print(f"  │ {line}")
        if len(lines) > 30:
            print(f"  │ ... ({len(lines) - 30} more lines)")

        path = save_result(phase, tool_cmd[1] if len(tool_cmd) > 1 else "unknown", data)
        state["phase_results"].setdefault(phase, []).append(str(path))

        return data

    except subprocess.TimeoutExpired:
        print("  ⏰ Timeout (120s)")
        return None
    except Exception as e:
        print(f"  ❌ Exception: {e}")
        return None


def analyze_with_llm(phase: str, prompt_file: str, tool_output: str):
    """Open LLM CLI with the prompt and tool output."""
    # Read prompt template
    prompt_path = Path("prompts") / prompt_file
    if not prompt_path.exists():
        print(f"  ❌ Prompt file not found: {prompt_path}")
        return

    prompt = prompt_path.read_text()
    prompt = prompt.replace("{{TARGET}}", state["target"])
    prompt = prompt.replace("{{TOOL_OUTPUT}}", tool_output)

    # Save the filled prompt
    session_dir = SESSION_DIR / state["session_id"]
    session_dir.mkdir(parents=True, exist_ok=True)
    filled_path = session_dir / f"{phase}_prompt.md"
    filled_path.write_text(prompt)

    # Also save the system prompt alongside
    system_path = Path("prompts/system.md")
    system_content = system_path.read_text() if system_path.exists() else ""

    combined_path = session_dir / f"{phase}_combined_prompt.md"
    combined_path.write_text(system_content + "\n\n---\n\n" + prompt)

    print(f"\n  📝 Prompt saved: {filled_path}")
    print(f"  📝 Combined prompt: {combined_path}")
    print()

    cmd = state["llm_cmd"]

    if cmd == "claude":
        print(f"  Run with Claude Code:")
        print(f"    cat {combined_path} | claude --print")
        print()
        print(f"  Or interactively:")
        print(f'    claude "$(cat {combined_path})"')

    elif cmd == "codex":
        print(f"  Run with Codex:")
        print(f"    cat {combined_path} | codex")

    elif cmd == "openclaw":
        print(f"  Run with OpenClaw:")
        print(f"    cat {combined_path} | openclaw chat")

    print()
    choice = input("  Execute now? [y/N/manual]: ").strip().lower()

    if choice == "y":
        if cmd == "claude":
            subprocess.run(["claude", "--print", "-p", str(combined_path)])
        elif cmd == "codex":
            subprocess.run(["codex", "-q", prompt], shell=False)
        elif cmd == "openclaw":
            subprocess.run(f"cat {combined_path} | openclaw chat", shell=True)
    elif choice == "manual":
        print(f"\n  Prompt is at: {combined_path}")
        print("  Copy-paste or pipe it to your preferred LLM.")
        input("  Press Enter when done...")


def collect_phase_output(phase: str) -> str:
    """Collect all tool outputs for a phase."""
    session_dir = SESSION_DIR / state["session_id"]
    outputs = []
    for path_str in state["phase_results"].get(phase, []):
        path = Path(path_str)
        if path.exists():
            outputs.append(path.read_text())
    return "\n---\n".join(outputs)


# ─── Menus ────────────────────────────────────────────────────

def menu_setup():
    """Initial setup: target URL and LLM choice."""
    clear()
    header()
    print("  ── Setup ──\n")

    target = input("  Target URL (e.g. https://example.com): ").strip()
    if not target:
        return False
    state["target"] = target

    from urllib.parse import urlparse
    parsed = urlparse(target)
    state["host"] = parsed.hostname or target
    state["port"] = parsed.port or (443 if parsed.scheme == "https" else 80)

    print()
    print("  LLM CLI を選択:")
    for key, (cmd, desc) in LLM_OPTIONS.items():
        print(f"    {key}) {desc} ({cmd})")
    choice = input("  選択 [1]: ").strip() or "1"
    if choice in LLM_OPTIONS:
        state["llm_cmd"] = LLM_OPTIONS[choice][0]

    return True


def menu_phase0():
    """Phase 0: Recon tools."""
    clear()
    header()
    print("  ── Phase 0: 偵察 (Recon) ──\n")
    print("    1) nmap ポートスキャン")
    print("    2) HTTP ヘッダ取得")
    print("    3) 証明書チェーン取得")
    print("    4) OpenAPI 仕様プローブ")
    print("    5) 全て実行")
    print("    a) 📊 LLMで分析")
    print("    b) ← 戻る")
    print()

    choice = input("  選択: ").strip()
    host, url = state["host"], state["target"]

    if choice == "1":
        run_tool("phase0", ["tools/recon.py", "nmap", host])
    elif choice == "2":
        run_tool("phase0", ["tools/recon.py", "headers", url])
    elif choice == "3":
        run_tool("phase0", ["tools/recon.py", "cert", host, "--port", str(state["port"])])
    elif choice == "4":
        run_tool("phase0", ["tools/recon.py", "openapi", url])
    elif choice == "5":
        run_tool("phase0", ["tools/recon.py", "all", url])
    elif choice == "a":
        output = collect_phase_output("phase0")
        if output:
            analyze_with_llm("phase0", "phase0-recon.md", output)
        else:
            print("  ⚠️  先にツールを実行してください")
    elif choice == "b":
        return "back"

    input("\n  Enter で続行...")


def menu_phase1():
    """Phase 1: TLS/SSH probing."""
    clear()
    header()
    print("  ── Phase 1: プロトコル層テスト ──\n")
    print("    1) TLS 暗号スイート列挙")
    print("    2) TLS バージョンテスト")
    print("    3) ダウングレード耐性テスト")
    print("    4) PQC 対応確認")
    print("    5) SSH プロービング")
    print("    6) TLS 全て実行")
    print("    a) 📊 LLMで分析")
    print("    b) ← 戻る")
    print()

    choice = input("  選択: ").strip()
    host = state["host"]
    port = str(state["port"])

    if choice == "1":
        run_tool("phase1", ["tools/tls.py", "ciphers", host, "--port", port])
    elif choice == "2":
        run_tool("phase1", ["tools/tls.py", "versions", host, "--port", port])
    elif choice == "3":
        run_tool("phase1", ["tools/tls.py", "downgrade", host, "--port", port])
    elif choice == "4":
        run_tool("phase1", ["tools/tls.py", "pqc", host, "--port", port])
    elif choice == "5":
        ssh_port = input("  SSHポート [22]: ").strip() or "22"
        run_tool("phase1", ["tools/tls.py", "ssh", host, "--port", ssh_port])
    elif choice == "6":
        run_tool("phase1", ["tools/tls.py", "all", host, "--port", port])
    elif choice == "a":
        output = collect_phase_output("phase1")
        if output:
            analyze_with_llm("phase1", "phase1-tls.md", output)
        else:
            print("  ⚠️  先にツールを実行してください")
    elif choice == "b":
        return "back"

    input("\n  Enter で続行...")


def menu_phase2():
    """Phase 2: Application layer."""
    clear()
    header()
    print("  ── Phase 2: アプリケーション層テスト ──\n")
    print("    1) 暗号文比較 (ECB/静的IV検出)")
    print("    2) JWT 解析")
    print("    3) トークン収集")
    print("    4) 乱数品質テスト (ファイルから)")
    print("    5) ハッシュ長分析")
    print("    a) 📊 LLMで分析")
    print("    b) ← 戻る")
    print()

    choice = input("  選択: ").strip()

    if choice == "1":
        url = input("  暗号化エンドポイントURL: ").strip()
        payload = input("  平文ペイロード: ").strip() or "AAAAAAAAAAAAAAAA" * 2
        n = input("  繰り返し回数 [10]: ").strip() or "10"
        run_tool("phase2", ["tools/app.py", "ciphertext", url, payload, "--n", n])
    elif choice == "2":
        token = input("  JWT トークン: ").strip()
        run_tool("phase2", ["tools/app.py", "jwt", token])
    elif choice == "3":
        url = input("  トークン取得URL: ").strip()
        n = input("  収集数 [100]: ").strip() or "100"
        run_tool("phase2", ["tools/app.py", "tokens", url, "--n", n])
    elif choice == "4":
        filepath = input("  トークンファイル (1行1トークン): ").strip()
        run_tool("phase2", ["tools/app.py", "randomness", filepath])
    elif choice == "5":
        hashes = input("  ハッシュ値 (スペース区切り): ").strip().split()
        if hashes:
            run_tool("phase2", ["tools/app.py", "hash-length"] + hashes)
    elif choice == "a":
        output = collect_phase_output("phase2")
        if output:
            analyze_with_llm("phase2", "phase2-app.md", output)
        else:
            print("  ⚠️  先にツールを実行してください")
    elif choice == "b":
        return "back"

    input("\n  Enter で続行...")


def menu_phase3():
    """Phase 3: Oracle & timing."""
    clear()
    header()
    print("  ── Phase 3: Oracle・タイミング解析 ──\n")
    print("    1) Padding Oracle テスト")
    print("    2) タイミング解析")
    print("    a) 📊 LLMで分析")
    print("    b) ← 戻る")
    print()

    choice = input("  選択: ").strip()

    if choice == "1":
        url = input("  復号エンドポイントURL: ").strip()
        ct = input("  暗号文 (hex or base64): ").strip()
        run_tool("phase3", ["tools/oracle.py", "padding", url, ct])
    elif choice == "2":
        url = input("  ターゲットURL: ").strip()
        p1 = input("  ペイロード1: ").strip()
        p2 = input("  ペイロード2: ").strip()
        n = input("  測定回数 [100]: ").strip() or "100"
        run_tool("phase3", ["tools/oracle.py", "timing", url, p1, p2, "--n", n])
    elif choice == "a":
        output = collect_phase_output("phase3")
        if output:
            analyze_with_llm("phase3", "phase3-oracle.md", output)
        else:
            print("  ⚠️  先にツールを実行してください")
    elif choice == "b":
        return "back"

    input("\n  Enter で続行...")


def menu_summary():
    """Generate final summary."""
    clear()
    header()
    print("  ── 最終サマリー ──\n")

    # Collect all findings from session
    session_dir = SESSION_DIR / state["session_id"]
    if not session_dir.exists():
        print("  ⚠️  まだツールを実行していません")
        input("\n  Enter で戻る...")
        return

    all_results = []
    for f in sorted(session_dir.glob("*.json")):
        all_results.append(f.read_text())

    combined = "\n---\n".join(all_results)
    analyze_with_llm("summary", "summarize.md", combined)
    input("\n  Enter で戻る...")


def menu_main():
    """Main menu."""
    while True:
        clear()
        header()
        print("  ── メインメニュー ──\n")
        print("    0) Phase 0: 偵察 (Recon)")
        print("    1) Phase 1: プロトコル層 (TLS/SSH)")
        print("    2) Phase 2: アプリケーション層")
        print("    3) Phase 3: Oracle・タイミング")
        print("    s) 📋 最終サマリー生成")
        print("    c) ⚙️  設定変更 (ターゲット/LLM)")
        print("    q) 終了")
        print()

        choice = input("  選択: ").strip().lower()

        if choice == "0":
            while menu_phase0() != "back":
                pass
        elif choice == "1":
            while menu_phase1() != "back":
                pass
        elif choice == "2":
            while menu_phase2() != "back":
                pass
        elif choice == "3":
            while menu_phase3() != "back":
                pass
        elif choice == "s":
            menu_summary()
        elif choice == "c":
            menu_setup()
        elif choice == "q":
            print("\n  👋 Bye!")
            break


# ─── Entry ────────────────────────────────────────────────────

if __name__ == "__main__":
    if not menu_setup():
        sys.exit(0)
    menu_main()
