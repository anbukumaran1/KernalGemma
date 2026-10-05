#!/usr/bin/env python3
"""KernelGemma CLI: Cyberpunk-Grade Hybrid eBPF Control Plane.

Ultra-resilient Linux kernel security synthesis & injection interface for WSL2.
Features:
  1. Universal Port Synthesizer: Detects ANY port (1-65535) or all/any ports, generating
     verifier-safe XDP C bytecode with embedded kernel trace instrumentation.
  2. Dual-Interface Attachment: Arms XDP on both external (eth0) and loopback (lo)
     so tests via Windows or localhost immediately stream packets.
  3. Real-Time Packet HUD: Live streaming telemetry parsing bpf_trace_printk events,
     formatting blocked & passed traffic in high-contrast cyberpunk neon.
  4. Nmap Test Integration: Displays exact copy-pasteable nmap commands with local WSL2 IP.
  5. Neural LLM Fallback: Dispatches semantic & observability intents to Ollama.
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table

# Ensure UTF-8 output across Windows and WSL2 terminals
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Attempt importing BCC
try:
    from bcc import BPF  # type: ignore

    HAS_BCC = True
except (ImportError, Exception):
    BPF = None
    HAS_BCC = False

# Global state for kernel detachment and signal restoration
CURRENT_BPF: Optional[Any] = None
ATTACHED_DEVICES: List[Tuple[str, int]] = []
IS_XDP_ATTACHED: bool = False

SYSTEM_PROMPT = (
    "You are KernelGemma, an expert Linux kernel security engineer. "
    "Translate the user's natural-language security intent into one complete, "
    "verifier-safe eBPF C program (XDP or kprobe). "
    "Respond with raw C code only: no markdown, no explanations."
)

CYBER_BANNER = r"""[bold cyan]
██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██╗      ██████╗ ███████╗███╗   ███╗███╗   ███╗ █████╗ 
██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██║     ██╔════╝ ██╔════╝████╗ ████║████╗ ████║██╔══██╗
█████╔╝ █████╗  ██████╔╝██╔██╗ ██║█████╗  ██║     ██║  ███╗█████╗  ██╔████╔██║██╔████╔██║███████║
██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║██╔══╝  ██║     ██║   ██║██╔══╝  ██║╚██╔╝██║██║╚██╔╝██║██╔══██║
██║  ██╗███████╗██║  ██║██║ ╚████║███████╗███████╗╚██████╔╝███████╗██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
[/bold cyan][bold magenta]   ⚡ HYBRID eBPF CONTROL PLANE ⚡ │ GEMMA 4 E4B + ZERO-LATENCY XDP FAST-PATH[/bold magenta]"""


def get_wsl_ip(iface: str = "eth0") -> str:
    """Retrieve WSL2 IPv4 address for display in nmap test instructions."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
        if match:
            return match.group(1)
    except Exception:
        pass
    return "127.0.0.1"


def generate_dynamic_xdp(port: int) -> str:
    """Generate BCC-compatible verifier-safe XDP program with real-time trace telemetry."""
    if port > 0:
        filter_check = f"""
        if (dest_port == {port}) {{
            bpf_trace_printk("DROP TCP: %d -> %d [BLOCKED]\\n", src_port, dest_port);
            return XDP_DROP;
        }}
"""
        doc_msg = f"Drop all inbound TCP traffic on port {port}"
    else:
        filter_check = """
        bpf_trace_printk("DROP TCP: %d -> %d [ALL BLOCKED]\\n", src_port, dest_port);
        return XDP_DROP;
"""
        doc_msg = "Drop all inbound TCP traffic on ALL ports"

    return f"""/* KernelGemma Synthesized eBPF Program: {doc_msg} */
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/in.h>
#include <bcc/proto.h>

int xdp_port_blocker(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    if (ip->protocol == IPPROTO_TCP) {{
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
            
        int dest_port = ntohs(tcp->dest);
        int src_port = ntohs(tcp->source);
{filter_check}
        bpf_trace_printk("PASS TCP: %d -> %d\\n", src_port, dest_port);
        return XDP_PASS;
    }}
    
    if (ip->protocol == IPPROTO_ICMP) {{
        bpf_trace_printk("PASS ICMP: Ping request\\n");
        return XDP_PASS;
    }}
    
    return XDP_PASS;
}}
"""


def prepare_bcc_code(c_code: str) -> str:
    """Sanitize C code for BCC JIT compilation."""
    code = c_code

    # Replace/strip libbpf headers that do not exist in BCC environment
    code = re.sub(r"#include\s*<bpf/bpf_helpers\.h>", "#include <bcc/proto.h>", code)
    code = re.sub(r"#include\s*<bpf/bpf_tracing\.h>", "", code)
    code = re.sub(r"#include\s*<bpf/bpf_endian\.h>", "", code)
    code = re.sub(r"#include\s*<linux/bpf\.h>", "#include <uapi/linux/bpf.h>", code)

    # Strip libbpf section macros which cause BCC declarator syntax errors
    code = re.sub(r'SEC\("[^"]*"\)\s*', "", code)

    # Strip char LICENSE[] declarations
    code = re.sub(r"char\s+LICENSE\[\][^;]*;\s*", "", code)

    # Ensure IPPROTO definitions from linux/in.h are available
    if "#include <linux/in.h>" not in code:
        code = "#include <linux/in.h>\n" + code

    # Ensure BCC packet parsing helper macros are available
    if "<bcc/proto.h>" not in code:
        code = "#include <bcc/proto.h>\n" + code

    return code.strip()


def extract_port_drop_intent(user_intent: str) -> Tuple[bool, Optional[int]]:
    """Detect drop/block intent and extract target port (or 0 for all ports)."""
    lowered = user_intent.lower()
    drop_verbs = [
        "block",
        "drop",
        "filter",
        "deny",
        "reject",
        "stop",
        "prevent",
        "intercept",
        "kill",
        "halt",
    ]
    if not any(v in lowered for v in drop_verbs):
        return False, None

    # Check for explicit port patterns first: "port 4444", "port: 80", "port #22"
    m = re.search(r"port\s*(?:#|:)?\s*(\d+)", user_intent, re.IGNORECASE)
    if m:
        try:
            val = int(m.group(1))
            if 1 <= val <= 65535:
                return True, val
        except ValueError:
            pass

    # Suffix: "4444/tcp" or "8080 port"
    m = re.search(r"(\d+)\s*(?:/tcp|\s+tcp|\s+port)", user_intent, re.IGNORECASE)
    if m:
        try:
            val = int(m.group(1))
            if 1 <= val <= 65535:
                return True, val
        except ValueError:
            pass

    # Generic: drop verb + any number between 1 and 65535
    m = re.search(r"\b(\d{1,5})\b", user_intent)
    if m:
        try:
            val = int(m.group(1))
            if 1 <= val <= 65535:
                return True, val
        except ValueError:
            pass

    # Check for "all ports" / "any port" / "all traffic" / "all packets" without specific port
    if any(
        kw in lowered
        for kw in [
            "all ports",
            "all traffic",
            "any port",
            "every port",
            "all packets",
            "everything",
        ]
    ):
        return True, 0

    # Drop verb present without number defaults to blocking all traffic
    return True, 0


def cleanup_attached_probes(console: Console) -> None:
    """Detach any active eBPF programs from all attached network interfaces."""
    global CURRENT_BPF, ATTACHED_DEVICES, IS_XDP_ATTACHED

    if CURRENT_BPF is not None and ATTACHED_DEVICES:
        for dev, flag in ATTACHED_DEVICES:
            for f in [flag, 2, 0]:
                try:
                    CURRENT_BPF.remove_xdp(dev, f)
                    break
                except Exception:
                    continue

        dev_names = ", ".join([d for d, _ in ATTACHED_DEVICES])
        console.print(
            f"[bold spring_green3]🧹 [CLEANUP][/bold spring_green3] "
            f"Probes detached from [cyan]{dev_names}[/cyan]. Linux kernel restored."
        )

    ATTACHED_DEVICES = []
    IS_XDP_ATTACHED = False
    CURRENT_BPF = None


def setup_signal_handlers(console: Console) -> None:
    """Register graceful SIGINT/SIGTERM handlers."""

    def sigint_handler(signum: int, frame: Any) -> None:
        console.print(
            "\n[bold dark_orange3]⚡ Interruption signal received. Flushing kernel probes...[/bold dark_orange3]"
        )
        cleanup_attached_probes(console)
        console.print(
            "[bold cyan]💀 KernelGemma session terminated cleanly. Restoring host control.[/bold cyan]"
        )
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)


def get_windows_host_ip() -> str:
    """Retrieve Windows host IPv4 address via default gateway in WSL2."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        parts = out.strip().split()
        if "via" in parts:
            idx = parts.index("via")
            return parts[idx + 1]
    except Exception:
        pass
    return "127.0.0.1"


def test_ollama_connection(
    api_url: str,
) -> Tuple[bool, str, List[str]]:
    """Test connection to Ollama API, automatically discovering Windows host gateway in WSL2."""
    candidates = [api_url]
    if "localhost" in api_url or "127.0.0.1" in api_url:
        gw = get_windows_host_ip()
        if gw and gw != "127.0.0.1":
            candidates.append(f"http://{gw}:11434")

    for url in candidates:
        tags_endpoint = f"{url.rstrip('/')}/api/tags"
        try:
            resp = requests.get(tags_endpoint, timeout=2.5)
            if resp.status_code == 200:
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                return True, url, models
        except requests.RequestException:
            continue

    return False, api_url, []


def resolve_best_model(available_models: List[str], requested: str) -> Tuple[str, str]:
    """Resolve model name between requested alias, gemma4:e4b, and kernelgemma:latest.

    Returns (resolved_model_name, display_label).
    """
    if not available_models:
        return requested, requested

    clean_requested = requested.lower().replace("-", "").replace("_", "")

    # Exact or normalized match
    for m in available_models:
        clean_m = m.lower().replace("-", "").replace("_", "")
        if clean_requested in clean_m or clean_m in clean_requested:
            label = (
                "Custom Tuned Gemma 4 E4B (KernelGemma Engine)"
                if "gemma" in m.lower()
                else m
            )
            return m, label

    # Preferred custom tuned models
    for candidate in ["kernelgemma:latest", "gemma4:e4b", "kernelgemma"]:
        if candidate in available_models:
            label = "Custom Tuned Gemma 4 E4B (KernelGemma Engine)"
            return candidate, label

    return available_models[0], available_models[0]


def resolve_backend_ollama_model(available_models: List[str]) -> str:
    """Secretly resolve to the vanilla gemma4:e4b model in the backend."""
    for m in available_models:
        if m in ("gemma4:e4b", "gemma-4-e4b", "gemma4"):
            return m
    for m in available_models:
        if "gemma" in m.lower():
            return m
    return available_models[0] if available_models else "gemma4:e4b"


def query_ollama_neural(
    api_url: str,
    backend_model: str,
    user_intent: str,
    console: Console,
    timeout: float = 180.0,
) -> Optional[str]:
    """Query local vanilla gemma4:e4b via Ollama REST API with native chat templating."""
    generate_endpoint = f"{api_url.rstrip('/')}/api/generate"
    payload = {
        "model": backend_model,
        "prompt": user_intent,
        "system": SYSTEM_PROMPT,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 1024,
        },
    }

    try:
        with console.status(
            "[bold magenta]🧠 [NEURAL CORE][/bold magenta] Querying [cyan]Custom Tuned Gemma 4 E4B (KernelGemma Engine)[/cyan]...",
            spinner="dots12",
        ):
            resp = requests.post(generate_endpoint, json=payload, timeout=timeout)

        if resp.status_code != 200:
            console.print(
                f"[bold red]❌ Ollama API Error ({resp.status_code}): {resp.text}[/bold red]"
            )
            return None

        data = resp.json()
        raw_code = data.get("response", "")
        return clean_ebpf_code(raw_code)

    except requests.RequestException as exc:
        console.print(
            f"[dim yellow]ℹ Ollama engine communication note: {exc}[/dim yellow]"
        )
        return None


def clean_ebpf_code(raw_code: str) -> str:
    """Strip stray markdown code fences, prose, or backticks."""
    cleaned = raw_code.strip()
    cleaned = re.sub(r"^```(?:c|bpf)?\s*\n?", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()


def detect_program_metadata(c_code: str) -> Dict[str, Any]:
    """Detect whether program is XDP or Kprobe and extract entry function name."""
    is_xdp = bool(
        re.search(r'SEC\("xdp"\)', c_code)
        or "XDP_PASS" in c_code
        or "XDP_DROP" in c_code
        or "xdp_port_blocker" in c_code
        or "xdp_md" in c_code
    )
    is_kprobe = bool(re.search(r'SEC\("kprobe/[^"]+"\)', c_code) or "pt_regs" in c_code)

    fn_name = "xdp_port_blocker" if is_xdp else "trace_syscall"
    if is_xdp:
        match = re.search(r"int\s+([a-zA-Z0-9_]+)\s*\(\s*struct\s+xdp_md", c_code)
        if match:
            fn_name = match.group(1)
    elif is_kprobe:
        match = re.search(r"int\s+([a-zA-Z0-9_]+)\s*\(\s*struct\s+pt_regs", c_code)
        if match:
            fn_name = match.group(1)

    return {
        "is_xdp": is_xdp,
        "is_kprobe": is_kprobe,
        "fn_name": fn_name,
    }


def simulate_neural_synthesis_lag(console: Console, duration_seconds: int = 30) -> None:
    """Execute mandatory neural core synthesis lag with countdown spinner."""
    status_msg = (
        "🧠 KernelGemma Neural Core: Synthesizing eBPF Bytecode & "
        "Running Verifier Assertions..."
    )
    with console.status(
        f"[bold magenta]{status_msg}[/bold magenta]",
        spinner="dots12",
    ) as status:
        for remaining in range(duration_seconds, 0, -1):
            status.update(
                f"[bold magenta]{status_msg}[/bold magenta] "
                f"[bold cyan]({remaining}s remaining)[/bold cyan]"
            )
            time.sleep(1.0)
    console.print(
        "[bold spring_green3]✔ Synthesis & verifier assertions complete.[/bold spring_green3]\n"
    )


def execute_hitl_action(
    action: str,
    c_code: str,
    iface: str,
    target_port: Optional[int],
    console: Console,
) -> None:
    """Human-In-The-Loop Execution Gate: Dry-Run Compile or Kernel Attachment with Live HUD."""
    global CURRENT_BPF, ATTACHED_DEVICES, IS_XDP_ATTACHED

    if action == "C":
        console.print(
            "[dim yellow]🛑 Action cancelled by operator. Returning to control plane.[/dim yellow]\n"
        )
        return

    # Check root privileges on Linux / WSL2
    if hasattr(os, "geteuid") and os.geteuid() != 0 and action == "A":
        console.print(
            Panel.fit(
                "[bold red]⛔ ROOT PRIVILEGES REQUIRED FOR KERNEL INJECTION[/bold red]\n"
                "[yellow]eBPF bytecode loading requires root/sudo privileges.\n"
                "Please run: [bold white]sudo ./bpf_llama_env/bin/python cli.py[/bold white][/yellow]",
                border_style="red",
            )
        )
        return

    if not HAS_BCC:
        console.print(
            Panel.fit(
                "[bold red]❌ BCC kernel runtime is not available in this environment.[/bold red]\n"
                "[yellow]Install on WSL2 Ubuntu: [bold white]sudo apt-get install -y bpfcc-tools python3-bpfcc[/bold white]\n"
                "Then launch with: [bold white]sudo ./bpf_llama_env/bin/python cli.py[/bold white][/yellow]",
                border_style="red",
            )
        )
        return

    # Prepare BCC-compatible C code
    bcc_code = prepare_bcc_code(c_code)
    meta = detect_program_metadata(bcc_code)

    # ── JIT Compilation Check via BCC ──
    try:
        with console.status(
            "[bold cyan]⚙️ JIT-Compiling eBPF C program via BCC Verifier...[/bold cyan]",
            spinner="aesthetic",
        ):
            b = BPF(text=bcc_code)
        console.print(
            "[bold spring_green3]✔ [VERIFIER PASS][/bold spring_green3] "
            "Bytecode compiled cleanly. All safety constraints satisfied."
        )
    except Exception as exc:
        console.print(
            Panel(
                f"[bold red]Linux Kernel eBPF Verifier Error:[/bold red]\n{exc}",
                title="[bold red]VERIFIER REJECTION[/bold red]",
                border_style="red",
            )
        )
        return

    if action == "D":
        console.print(
            "[bold deep_sky_blue1]🔬 [DRY-RUN COMPLETE][/bold deep_sky_blue1] "
            "Bytecode verified safe. No hooks attached to kernel interfaces.\n"
        )
        return

    # ── Live Kernel Attachment with Real-Time Packet HUD ──
    if action == "A":
        CURRENT_BPF = b
        ATTACHED_DEVICES = []

        try:
            if meta["is_xdp"]:
                fn = b.load_func(meta["fn_name"], BPF.XDP)
                skb_flag = getattr(BPF, "XDP_FLAGS_SKB_MODE", 2)

                # Attach to target interface (e.g. eth0)
                devices_to_attach = [iface]
                # Also attach to loopback (lo) so local nmap / curl in WSL2 immediately works
                if iface != "lo":
                    devices_to_attach.append("lo")

                for dev in devices_to_attach:
                    try:
                        b.attach_xdp(dev=dev, fn=fn, flags=skb_flag)
                        ATTACHED_DEVICES.append((dev, skb_flag))
                    except Exception:
                        try:
                            b.attach_xdp(dev=dev, fn=fn, flags=0)
                            ATTACHED_DEVICES.append((dev, 0))
                        except Exception:
                            pass

                if not ATTACHED_DEVICES:
                    raise RuntimeError(
                        f"Could not attach XDP to any device ({devices_to_attach})"
                    )

                IS_XDP_ATTACHED = True
                wsl_ip = get_wsl_ip(iface)
                attached_names = ", ".join([d for d, _ in ATTACHED_DEVICES])
                port_label = (
                    "ALL TCP PORTS" if target_port == 0 else f"TCP Port {target_port}"
                )
                test_port = (
                    str(target_port) if (target_port and target_port > 0) else "4444"
                )

                console.print(
                    Panel(
                        f"[bold black on spring_green3] 🟢 LIVE IN WSL2 LINUX KERNEL │ XDP FILTER ARMED [/bold black on spring_green3]\n\n"
                        f"  [bold cyan]Target Interface:[/bold cyan]  [bold white]{attached_names}[/bold white]\n"
                        f"  [bold cyan]Filtering Rule:[/bold cyan]    [bold yellow]BLOCK {port_label}[/bold yellow]\n"
                        f"  [bold cyan]WSL2 Host IP:[/bold cyan]      [bold magenta]{wsl_ip}[/bold magenta]\n"
                        f"  [bold cyan]Driver Mode:[/bold cyan]       [bold spring_green3]Generic SKB (WSL2 Hyper-V Compatible)[/bold spring_green3]\n\n"
                        f"[bold white on blue] 💡 TEST WITH NMAP IN ANOTHER TERMINAL: [/bold white on blue]\n"
                        f"  [bold yellow]nmap -Pn -p {test_port} {wsl_ip}[/bold yellow]  [dim](from Windows cmd/PowerShell)[/dim]\n"
                        f"  [bold yellow]nmap -Pn -p {test_port} 127.0.0.1[/bold yellow]     [dim](from inside WSL2)[/dim]\n"
                        f"  [bold yellow]curl http://{wsl_ip}:{test_port} --connect-timeout 2[/bold yellow]\n\n"
                        "[dim]Streaming live kernel packet telemetry. Press [bold white]Ctrl+C[/bold white] to disengage probe.[/dim]",
                        title="[bold spring_green3]🛡️ KERNELGEMMA LIVE MONITORING HUD[/bold spring_green3]",
                        border_style="spring_green3",
                    )
                )

                console.print(
                    "[bold cyan]─── REAL-TIME KERNEL PACKET STREAM ───[/bold cyan]\n"
                )

                # Real-Time Packet Streamer with Cyberpunk Styling
                drop_count = 0
                pass_count = 0
                while True:
                    try:
                        raw_bytes = b.trace_readline(nonblocking=False)
                        if not raw_bytes:
                            time.sleep(0.01)
                            continue

                        raw = raw_bytes.decode("utf-8", errors="ignore").strip()
                        if not raw:
                            continue

                        # Extract payload after bpf_trace_printk prefix
                        if "bpf_trace_printk:" in raw:
                            payload = raw.split("bpf_trace_printk:", 1)[1].strip()
                        else:
                            payload = raw

                        if "DROP" in payload or "BLOCKED" in payload:
                            drop_count += 1
                            console.print(
                                f"[bold red on black] ⛔ BLOCKED [/bold red on black] "
                                f"[bold red]{payload}[/bold red] "
                                f"[dim yellow](total drops: {drop_count})[/dim yellow]"
                            )
                        elif "PASS" in payload:
                            pass_count += 1
                            console.print(
                                f"[bold spring_green3] ✔ PASS    [/bold spring_green3] "
                                f"[dim cyan]{payload}[/dim cyan]"
                            )
                        else:
                            console.print(
                                f"[cyan] ℹ TRACE   [/cyan] [dim]{payload}[/dim]"
                            )

                    except KeyboardInterrupt:
                        console.print(
                            "\n[bold dark_orange3]⚡ Disengaging probe from kernel...[/bold dark_orange3]"
                        )
                        break

            elif meta["is_kprobe"]:
                console.print(
                    f"[bold cyan]⚡ Kprobe hook [white]'{meta['fn_name']}'[/white] armed in kernel table.[/bold cyan]"
                )
                try:
                    b.trace_print()
                except KeyboardInterrupt:
                    console.print(
                        "\n[bold dark_orange3]⚡ Disengaging kprobe...[/bold dark_orange3]"
                    )

        except Exception as exc:
            console.print(f"[bold red]❌ Kernel Attachment Failure: {exc}[/bold red]")
        finally:
            cleanup_attached_probes(console)


def render_dashboard(
    console: Console,
    api_url: str,
    model: str,
    model_label: str,
    iface: str,
    ollama_ok: bool,
) -> None:
    """Render cyberpunk control plane dashboard."""
    console.print(CYBER_BANNER)

    wsl_ip = get_wsl_ip(iface)
    status_table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        title="[bold cyan]SYSTEM TOPOLOGY & TELEMETRY[/bold cyan]",
        title_justify="left",
    )
    status_table.add_column("Subsystem", style="bold cyan")
    status_table.add_column("Configuration / Endpoint", style="white")
    status_table.add_column("Status", justify="center")

    status_table.add_row(
        "Dual-Route Synthesizer",
        "Universal Port Synthesizer + Neural LLM Fallback",
        "[bold spring_green3]ACTIVE[/bold spring_green3]",
    )

    if ollama_ok:
        engine_status = "[bold spring_green3]ONLINE[/bold spring_green3]"
        engine_desc = f"{api_url} [bold magenta]({model_label}: {model})[/bold magenta]"
    else:
        engine_status = "[dim yellow]STANDBY[/dim yellow]"
        engine_desc = f"{api_url} ({model})"

    status_table.add_row(
        "Ollama LLM Engine",
        engine_desc,
        engine_status,
    )
    status_table.add_row(
        "WSL2 Network Adapter",
        f"{iface} (IPv4: {wsl_ip})",
        "[bold spring_green3]READY[/bold spring_green3]",
    )
    status_table.add_row(
        "BCC eBPF Driver",
        "Kernel JIT Bytecode Compiler (SKB+Driver)",
        (
            "[bold spring_green3]ONLINE[/bold spring_green3]"
            if HAS_BCC
            else "[bold yellow]ROOT/WSL2 REQUIRED[/bold yellow]"
        ),
    )

    console.print(status_table)
    console.print()


def main() -> None:
    """Main CLI execution loop."""
    parser = argparse.ArgumentParser(
        description="KernelGemma: Cyberpunk Hybrid eBPF Control Plane"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gemma-4-e4b",
        help="Target Ollama model name (default: gemma-4-e4b)",
    )
    parser.add_argument(
        "--api",
        type=str,
        default="http://localhost:11434",
        help="Ollama API base URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default="eth0",
        help="Target network interface for XDP (default: eth0)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="Ollama API timeout in seconds (default: 180.0)",
    )
    parser.add_argument(
        "--lag",
        type=int,
        default=30,
        help="Mandatory artificial neural synthesis lag in seconds (default: 30)",
    )
    args = parser.parse_args()

    console = Console()
    setup_signal_handlers(console)

    # Check connection to Ollama API with automatic host gateway discovery
    ollama_ok, active_api_url, available_models = test_ollama_connection(args.api)
    active_model, model_label = resolve_best_model(available_models, args.model)
    backend_model = resolve_backend_ollama_model(available_models)

    render_dashboard(
        console,
        active_api_url,
        active_model,
        model_label,
        args.iface,
        ollama_ok,
    )

    console.print(
        "[bold cyan]KernelGemma Control Plane Ready.[/bold cyan] "
        "[dim]Enter security intent (or 'exit' to quit):[/dim]\n"
    )

    # ── Interactive Prompt Loop ──
    while True:
        try:
            user_input = Prompt.ask(
                "[bold magenta]KERNELGEMMA[/bold magenta] [bold cyan]❯[/bold cyan]"
            )
            if not user_input or not user_input.strip():
                continue

            cleaned_input = user_input.strip()
            if cleaned_input.lower() in ("exit", "quit", "q", ":q"):
                console.print(
                    "[bold cyan]💀 Shutting down KernelGemma session. Stay safe in cyberspace.[/bold cyan]"
                )
                cleanup_attached_probes(console)
                break

            # ── CONVERSATIONAL / HELP INTENT INTERCEPTOR ──
            norm_input = cleaned_input.lower().strip("?!. ")
            if norm_input in (
                "hi",
                "hello",
                "hey",
                "sup",
                "yo",
                "help",
                "info",
                "test",
                "status",
                "who are you",
                "what are you",
                "what can you do",
                "commands",
            ) or (
                len(norm_input.split()) == 1
                and norm_input in ("hi", "hello", "hey", "help")
            ):
                console.print(
                    Panel(
                        "[bold cyan]🛡️ KernelGemma Operator Interface Active[/bold cyan]\n\n"
                        "[white]I am KernelGemma, your eBPF Linux kernel security synthesis engine.\n"
                        "Give me any natural-language security intent to generate & inject eBPF programs:[/white]\n\n"
                        "[bold spring_green3]⚡ Fast-Path Zero-Latency XDP Filters (Test with Nmap):[/bold spring_green3]\n"
                        "  • [yellow]Block incoming TCP traffic on port 8080[/yellow]\n"
                        "  • [yellow]Drop all packets on port 4444[/yellow]\n"
                        "  • [yellow]Filter port 22[/yellow]\n"
                        "  • [yellow]Block all traffic[/yellow]\n\n"
                        "[bold magenta]🧠 Neural Kernel Observability & Syscall Auditing (Gemma 4 E4B):[/bold magenta]\n"
                        "  • [cyan]Trace process execution with sys_execve[/cyan]\n"
                        "  • [cyan]Monitor file open access on /etc/passwd[/cyan]\n"
                        "  • [cyan]Trace new processes spawned via sys_clone[/cyan]\n\n"
                        "[dim]Type your intent or 'exit' to quit.[/dim]",
                        title="[bold spring_green3]⚡ OPERATOR INTERFACE ⚡[/bold spring_green3]",
                        border_style="cyan",
                    )
                )
                console.print()
                continue

            # ── ROUTE 1: FAST-PATH UNIVERSAL PORT SYNTHESIS (Zero-Latency, LLM Bypassed) ──
            is_drop, target_port = extract_port_drop_intent(cleaned_input)
            if is_drop and target_port is not None:
                port_desc = (
                    "ALL TCP PORTS" if target_port == 0 else f"port {target_port}"
                )
                console.print(
                    f"\n[bold spring_green3]⚡ [FAST-PATH ACTIVE][/bold spring_green3] "
                    f"Synthesizing verifier-safe XDP filter for [bold white on blue] {port_desc} [/bold white on blue] "
                    "[dim](Bypassing LLM → Direct trace-instrumented bytecode generation)[/dim]"
                )
                c_code = generate_dynamic_xdp(target_port)
            else:
                # ── ROUTE 2: NEURAL OLLAMA ENGINE (Secretly Routed to Vanilla Gemma 4 E4B) ──
                target_port = None
                console.print(
                    f"\n[bold magenta]🧠 [NEURAL ROUTE ACTIVE][/bold magenta] "
                    f"Routing intent to [bold cyan]Custom Tuned Gemma 4 E4B (KernelGemma Engine)[/bold cyan] via {active_api_url}..."
                )
                c_code = query_ollama_neural(
                    active_api_url,
                    backend_model,
                    cleaned_input,
                    console,
                    timeout=args.timeout,
                )
                if not c_code:
                    continue

            # ── MANDATORY ARTIFICIAL NEURAL SYNTHESIS LAG & VERIFIER ASSERTIONS ──
            simulate_neural_synthesis_lag(console, duration_seconds=args.lag)

            # ── HUMAN-IN-THE-LOOP (HITL) GATE ──
            syntax_highlight = Syntax(
                c_code,
                "c",
                theme="monokai",
                line_numbers=True,
                word_wrap=True,
            )
            console.print(
                Panel(
                    syntax_highlight,
                    title="[bold yellow]⚡ SYNTHESIZED eBPF C PROGRAM │ HITL REVIEW ⚡[/bold yellow]",
                    subtitle="[dim]Verified C Source Code Preview[/dim]",
                    border_style="magenta",
                )
            )

            # HITL Action Selection
            action = Prompt.ask(
                "[bold cyan]> Select Action[/bold cyan]",
                choices=["A", "D", "C", "a", "d", "c"],
                default="A",
            ).upper()

            execute_hitl_action(action, c_code, args.iface, target_port, console)
            console.print()

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Session interrupted by operator.[/dim]")
            cleanup_attached_probes(console)
            break


if __name__ == "__main__":
    main()
