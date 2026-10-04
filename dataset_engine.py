"""KernelGemma Synthetic Dataset Engine.

Generates verifier-safe eBPF C dataset for fine-tuning Gemma 4 E4B.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import io
import json
import logging
import os
import random
import re
import shutil
import subprocess
import sys
import time
from typing import Any

import aiohttp
from dotenv import load_dotenv
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

# ====================================================================
# MODULE CONSTANTS
# ====================================================================

SYSTEM_PROMPT: str = (
    "You are KernelGemma, an expert Linux kernel security engineer. "
    "Translate the user's natural-language security intent into one "
    "complete, verifier-safe eBPF C program (XDP or kprobe). "
    "Respond with raw C code only: no markdown, no explanations."
)

MANDATORY_INCLUDES: tuple[str, ...] = (
    "#include <uapi/linux/bpf.h>",
    "#include <linux/in.h>",
    "#include <linux/if_ether.h>",
    "#include <linux/ip.h>",
)

ALLOWED_EXTRA_INCLUDES: frozenset[str] = frozenset(
    {
        "<linux/tcp.h>",
        "<linux/udp.h>",
        "<linux/icmp.h>",
        "<linux/ptrace.h>",
        "<bpf/bpf_helpers.h>",
        "<bpf/bpf_endian.h>",
        "<bpf/bpf_tracing.h>",
    }
)

WHITELISTED_HELPERS: frozenset[str] = frozenset(
    {
        "bpf_map_lookup_elem",
        "bpf_map_update_elem",
        "bpf_map_delete_elem",
        "bpf_ktime_get_ns",
        "bpf_get_smp_processor_id",
        "bpf_get_current_pid_tgid",
        "bpf_get_current_uid_gid",
        "bpf_get_current_comm",
        "bpf_probe_read_kernel",
        "bpf_probe_read_user",
        "bpf_probe_read_user_str",
        "bpf_ringbuf_reserve",
        "bpf_ringbuf_submit",
        "bpf_ringbuf_discard",
        "bpf_printk",
        "bpf_htons",
        "bpf_htonl",
        "bpf_ntohs",
        "bpf_ntohl",
    }
)

ALLOWED_PROGRAM_SECS: frozenset[str] = frozenset(
    {
        "xdp",
        "kprobe/__x64_sys_execve",
        "kprobe/__x64_sys_openat",
    }
)

ALLOWED_ALL_SECS: frozenset[str] = frozenset(
    {
        "xdp",
        "kprobe/__x64_sys_execve",
        "kprobe/__x64_sys_openat",
        "license",
        ".maps",
    }
)

FORBIDDEN_HOOK_KEYWORDS: frozenset[str] = frozenset(
    {
        "tracepoint",
        "tc",
        "classifier",
        "raw_tp",
        "socket",
        "cgroup",
        "lsm",
        "fentry",
        "fexit",
        "uprobe",
    }
)

FORBIDDEN_KPROBE_HELPERS: frozenset[str] = frozenset(
    {
        "bpf_override_return",
        "bpf_send_signal",
        "bpf_probe_write_user",
    }
)

FORBIDDEN_XDP_RETURNS: frozenset[str] = frozenset(
    {
        "XDP_TX",
        "XDP_REDIRECT",
        "XDP_ABORTED",
    }
)

FORBIDDEN_LIBC_CALLS: frozenset[str] = frozenset(
    {
        "printf",
        "memcpy",
        "strcmp",
        "strlen",
        "malloc",
        "free",
        "sprintf",
        "memset",
        "strncpy",
        "strcpy",
    }
)

CATEGORY_BASE_QUOTAS: dict[str, int] = {
    "X1": 30,
    "X2": 25,
    "X3": 25,
    "X4": 20,
    "X5": 25,
    "X6": 20,
    "X7": 15,
    "X8": 10,
    "X9": 10,
    "K1": 30,
    "K2": 30,
    "K3": 20,
    "K4": 20,
    "K5": 20,
}

GENERATOR_RULEBOOK: str = (
    "You write training data for a model that must emit eBPF C code\n"
    "accepted by the Linux kernel verifier with ZERO errors. Output\n"
    'JSON {"intent": ..., "code": ...} only.\n\n'
    "UNIVERSAL RULES\n"
    "U1. Every program starts with these four includes (in this order),\n"
    "then any extras from the whitelist: #include <uapi/linux/bpf.h>,\n"
    "#include <linux/in.h>, #include <linux/if_ether.h>,\n"
    "#include <linux/ip.h>. Allowed extras: <linux/tcp.h>,\n"
    "<linux/udp.h>, <linux/icmp.h>, <linux/ptrace.h>,\n"
    "<bpf/bpf_helpers.h>, <bpf/bpf_endian.h>, <bpf/bpf_tracing.h>.\n"
    "Every program includes <bpf/bpf_helpers.h>. No libc headers.\n"
    'U2. Every program ends with char LICENSE[] SEC("license") = "GPL";\n'
    "U3. Exactly one program function per file, preceded by one SEC(...).\n"
    "Helpers are static __always_inline.\n"
    "U4. No unbounded loops. No while, no for(;;). Any loop has a\n"
    "compile-time constant bound of at most 32 and #pragma unroll.\n"
    "U5. No libc (printf, memcpy, strcmp, strlen, malloc). No floating\n"
    "point. No recursion. No global mutable state outside BPF maps.\n"
    "U6. Stack use stays under 256 bytes. Initialize every local buffer\n"
    "(= {}).\n"
    "U7. Every bpf_map_lookup_elem result is NULL-checked before\n"
    "dereference.\n"
    "U8. Whitelisted helpers ONLY: bpf_map_lookup_elem, bpf_map_update_elem,\n"
    "bpf_map_delete_elem, bpf_ktime_get_ns, bpf_get_smp_processor_id,\n"
    "bpf_get_current_pid_tgid, bpf_get_current_uid_gid,\n"
    "bpf_get_current_comm, bpf_probe_read_kernel, bpf_probe_read_user,\n"
    "bpf_probe_read_user_str, bpf_ringbuf_reserve, bpf_ringbuf_submit,\n"
    "bpf_ringbuf_discard, bpf_printk (at most 3 format args), bpf_htons,\n"
    "bpf_htonl, bpf_ntohs, bpf_ntohl.\n"
    "U9. Maps use BTF-style .maps definitions (__uint, __type). Use LRU\n"
    "hash for per-source tracking. Increment counters with\n"
    "__sync_fetch_and_add.\n"
    "U10. Only sparse single-line // comments. No block comments.\n"
    "U11. No markdown fences or prose in code.\n\n"
    "XDP RULES\n"
    'X-A. Signature: int <name>(struct xdp_md *ctx) with SEC("xdp").\n'
    "X-B. MANDATORY prologue before ANY header dereference, verbatim:\n"
    "    void *data = (void *)(long)ctx->data;\n"
    "    void *data_end = (void *)(long)ctx->data_end;\n"
    "    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)\n"
    "        return XDP_PASS;\n"
    "X-C. Then check eth->h_proto != bpf_htons(ETH_P_IP) and\n"
    "return XDP_PASS. IPv6 and non-IP traffic always pass.\n"
    "X-D. Before touching TCP/UDP/ICMP, validate\n"
    "ip->ihl * 4 >= sizeof(struct iphdr). Compute L4 as\n"
    "(void *)ip + ihl_bytes. Bounds-check the L4 header against data_end\n"
    "and return XDP_PASS on failure.\n"
    "X-E. Return ONLY XDP_DROP or XDP_PASS. Never XDP_TX, XDP_REDIRECT,\n"
    "XDP_ABORTED. Fail-open (PASS) on every parse failure.\n"
    "X-F. Byte order: compare header fields against bpf_htons()/bpf_htonl()\n"
    "constants. Never compare host-order values to raw fields.\n"
    "X-G. Header/offset arithmetic never uses unchecked variable offsets.\n\n"
    "KPROBE RULES\n"
    'K-A. SEC("kprobe/__x64_sys_execve") or SEC("kprobe/__x64_sys_openat")\n'
    "only. Signature: int <name>(struct pt_regs *ctx). Always return 0;.\n"
    "K-B. #define __TARGET_ARCH_x86 appears before\n"
    "#include <bpf/bpf_tracing.h>.\n"
    "K-C. The syscall wrapper passes the real regs in PARM1. Read arguments\n"
    "exactly like this:\n"
    "    struct pt_regs *sregs = (struct pt_regs *)PT_REGS_PARM1(ctx);\n"
    "    bpf_probe_read_kernel(&ptr, sizeof(ptr), &PT_REGS_PARM1(sregs));\n"
    "  (execve filename = PARM1; openat filename = PARM2.) Then\n"
    "bpf_probe_read_user_str(buf, sizeof(buf), ptr).\n"
    "K-D. String matching is a bounded, unrolled byte loop against a\n"
    "static const char pattern (bound at most 32), never libc.\n"
    "K-E. Observability only: no bpf_override_return, bpf_send_signal,\n"
    "bpf_probe_write_user. Emit events through bpf_printk (at most 3 args)\n"
    "or a ring buffer (reserve, NULL check, fill, submit)."
)

GOLD_EXEMPLARS: str = (
    'Exemplar A (X1), intent: "Drop all inbound traffic from 203.0.113.50 '
    'at the earliest point in the network stack."\n'
    "#include <uapi/linux/bpf.h>\n"
    "#include <linux/in.h>\n"
    "#include <linux/if_ether.h>\n"
    "#include <linux/ip.h>\n"
    "#include <bpf/bpf_helpers.h>\n"
    "#include <bpf/bpf_endian.h>\n\n"
    'SEC("xdp")\n'
    "int xdp_drop_src_ip(struct xdp_md *ctx)\n"
    "{\n"
    "    void *data = (void *)(long)ctx->data;\n"
    "    void *data_end = (void *)(long)ctx->data_end;\n\n"
    "    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)\n"
    "        return XDP_PASS;\n\n"
    "    struct ethhdr *eth = data;\n"
    "    if (eth->h_proto != bpf_htons(ETH_P_IP))\n"
    "        return XDP_PASS;\n\n"
    "    struct iphdr *ip = data + sizeof(struct ethhdr);\n"
    "    if (ip->saddr == bpf_htonl(0xCB007132))\n"
    "        return XDP_DROP;\n\n"
    "    return XDP_PASS;\n"
    "}\n\n"
    'char LICENSE[] SEC("license") = "GPL";\n\n'
    'Exemplar B (K1), intent: "Log every process execution on the host '
    'with the PID, command name, and binary path."\n'
    "#include <uapi/linux/bpf.h>\n"
    "#include <linux/in.h>\n"
    "#include <linux/if_ether.h>\n"
    "#include <linux/ip.h>\n"
    "#include <linux/ptrace.h>\n"
    "#define __TARGET_ARCH_x86\n"
    "#include <bpf/bpf_helpers.h>\n"
    "#include <bpf/bpf_tracing.h>\n\n"
    "#define COMM_LEN 16\n"
    "#define PATH_LEN 128\n\n"
    'SEC("kprobe/__x64_sys_execve")\n'
    "int trace_execve(struct pt_regs *ctx)\n"
    "{\n"
    "    struct pt_regs *sregs = (struct pt_regs *)PT_REGS_PARM1(ctx);\n"
    "    const char *filename_ptr = NULL;\n"
    "    char filename[PATH_LEN] = {};\n"
    "    char comm[COMM_LEN] = {};\n"
    "    __u32 pid = bpf_get_current_pid_tgid() >> 32;\n\n"
    "    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr),\n"
    "                          &PT_REGS_PARM1(sregs));\n"
    "    bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);\n"
    "    bpf_get_current_comm(comm, sizeof(comm));\n"
    '    bpf_printk("execve pid=%d comm=%s file=%s", pid, comm, filename);\n'
    "    return 0;\n"
    "}\n\n"
    'char LICENSE[] SEC("license") = "GPL";\n'
)

# ====================================================================
# DATA MODELS
# ====================================================================


@dataclasses.dataclass(frozen=True)
class JobSpec:
    """Specification for a single training dataset row."""

    job_id: str
    category: str
    tier: str
    style: str
    hook_mention: str
    params: dict[str, Any]
    attempt: int = 0


@dataclasses.dataclass
class AcceptedRow:
    """Accepted dataset record stored in output and manifest."""

    job_id: str
    category: str
    intent: str
    code: str
    intent_hash: str
    code_hash: str
    params: dict[str, Any]
    tier: str
    style: str
    timestamp: float


# ====================================================================
# VALIDATION HELPER FUNCTIONS
# ====================================================================


def normalize_intent(intent: str) -> str:
    """Normalize intent for deduplication."""
    return " ".join(intent.strip().lower().split())


def normalize_code(code: str) -> str:
    """Normalize code by removing comments and whitespace."""
    no_comments = re.sub(r"//.*", "", code)
    no_block_comments = re.sub(r"/\*[\s\S]*?\*/", "", no_comments)
    return "".join(no_block_comments.split())


def compute_intent_hash(intent: str) -> str:
    """Compute SHA-256 hash of normalized intent."""
    return hashlib.sha256(normalize_intent(intent).encode("utf-8")).hexdigest()


def compute_code_hash(code: str) -> str:
    """Compute SHA-256 hash of normalized code."""
    return hashlib.sha256(normalize_code(code).encode("utf-8")).hexdigest()


def jaccard_similarity(intent1: str, intent2: str) -> float:
    """Calculate token Jaccard similarity between two intents."""
    tokens1 = set(re.findall(r"\w+", intent1.lower()))
    tokens2 = set(re.findall(r"\w+", intent2.lower()))
    if not tokens1 and not tokens2:
        return 1.0
    union = tokens1 | tokens2
    if not union:
        return 0.0
    return len(tokens1 & tokens2) / len(union)


def _check_balanced_delimiters(code: str) -> list[str]:
    """Verify braces and parentheses are properly balanced."""
    reasons: list[str] = []
    # Strip comments and string literals to prevent false counts
    stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    stripped = re.sub(r"//.*", "", stripped)

    brace_depth = 0
    paren_depth = 0
    for char in stripped:
        if char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth -= 1
            if brace_depth < 0:
                reasons.append("Unbalanced closing brace '}'.")
                break
        elif char == "(":
            paren_depth += 1
        elif char == ")":
            paren_depth -= 1
            if paren_depth < 0:
                reasons.append("Unbalanced closing parenthesis ')'.")
                break

    if brace_depth > 0:
        reasons.append(f"Unclosed opening brace '{{' (depth {brace_depth}).")
    if paren_depth > 0:
        reasons.append(
            f"Unclosed opening parenthesis '(' (depth {paren_depth})."
        )
    return reasons


def _check_includes(code: str) -> list[str]:
    """Verify include order, whitelist, and helpers include."""
    reasons: list[str] = []
    include_matches = list(re.finditer(r"#include\s*([<\"].+?[>\"])", code))
    include_headers = [m.group(1).strip() for m in include_matches]

    if len(include_headers) < 4:
        reasons.append(
            "Program has fewer than the 4 mandatory includes: "
            f"found {len(include_headers)}."
        )
        return reasons

    first_four = tuple(f"#include {h}" for h in include_headers[:4])
    if first_four != MANDATORY_INCLUDES:
        reasons.append(
            "First 4 includes must be exactly "
            "<uapi/linux/bpf.h>, <linux/in.h>, <linux/if_ether.h>, "
            f"<linux/ip.h> in order. Found: {first_four}."
        )

    for hdr in include_headers:
        if (
            hdr
            not in {
                "<uapi/linux/bpf.h>",
                "<linux/in.h>",
                "<linux/if_ether.h>",
                "<linux/ip.h>",
            }
            and hdr not in ALLOWED_EXTRA_INCLUDES
        ):
            reasons.append(f"Disallowed include header: {hdr}.")

    if "<bpf/bpf_helpers.h>" not in include_headers:
        reasons.append("Missing mandatory include: <bpf/bpf_helpers.h>.")

    return reasons


def _check_sections(code: str) -> tuple[list[str], str | None]:
    """Verify SEC(...) macros and return detected program SEC."""
    reasons: list[str] = []
    secs = re.findall(r'SEC\(\s*"([^"]+)"\s*\)', code)

    for sec in secs:
        if sec not in ALLOWED_ALL_SECS:
            reasons.append(f'Disallowed SEC section: SEC("{sec}").')

    for forbidden in FORBIDDEN_HOOK_KEYWORDS:
        for sec in secs:
            if forbidden in sec:
                reasons.append(
                    f"Forbidden hook type '{forbidden}' in SEC(\"{sec}\")."
                )

    prog_secs = [s for s in secs if s in ALLOWED_PROGRAM_SECS]
    if len(prog_secs) != 1:
        reasons.append(
            f"Expected exactly 1 program SEC, but found {len(prog_secs)}: "
            f"{prog_secs}."
        )
        return reasons, None

    return reasons, prog_secs[0]


def _check_xdp_rules(code: str) -> list[str]:
    """Validate XDP-specific rules."""
    reasons: list[str] = []
    bounds_pat = (
        r"data\s*\+\s*sizeof\s*\(\s*struct\s+ethhdr\s*\)\s*\+\s*"
        r"sizeof\s*\(\s*struct\s+iphdr\s*\)\s*>\s*data_end"
    )
    bounds_match = re.search(bounds_pat, code)
    if not bounds_match:
        reasons.append(
            "Missing mandatory XDP bounds-check: "
            "data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end."
        )
    else:
        # Must appear before any eth-> or ip-> dereference
        first_eth = code.find("eth->")
        first_ip = code.find("ip->")
        if (first_eth != -1 and first_eth < bounds_match.start()) or (
            first_ip != -1 and first_ip < bounds_match.start()
        ):
            reasons.append(
                "Mandatory XDP bounds-check must appear BEFORE first eth-> "
                "or ip-> dereference."
            )

    if not re.search(r"\breturn\s+XDP_PASS\s*;", code):
        reasons.append("XDP program must contain 'return XDP_PASS;'.")

    for ret in FORBIDDEN_XDP_RETURNS:
        if re.search(rf"\b{ret}\b", code):
            reasons.append(
                f"Forbidden XDP action '{ret}' used. Only XDP_DROP and "
                "XDP_PASS allowed."
            )

    # L4 headers bounds checks
    for l4_hdr in ("tcphdr", "udphdr", "icmphdr"):
        if re.search(rf"\bstruct\s+{l4_hdr}\b", code) or re.search(
            rf"\b{l4_hdr}\s*\*", code
        ):
            if not re.search(r">\s*data_end\b", code):
                reasons.append(
                    f"L4 header {l4_hdr} used without bounds check "
                    "against data_end."
                )

    return reasons


def _check_kprobe_rules(code: str) -> list[str]:
    """Validate kprobe-specific rules."""
    reasons: list[str] = []
    arch_pos = code.find("#define __TARGET_ARCH_x86")
    tracing_pos = code.find("<bpf/bpf_tracing.h>")
    if tracing_pos != -1:
        if arch_pos == -1 or arch_pos > tracing_pos:
            reasons.append(
                "#define __TARGET_ARCH_x86 must appear before "
                "#include <bpf/bpf_tracing.h>."
            )
    elif arch_pos == -1:
        reasons.append("Missing #define __TARGET_ARCH_x86 in kprobe program.")

    if not re.search(r"\breturn\s+0\s*;\s*\}", code):
        reasons.append("kprobe program function must end with 'return 0;'.")

    for mutator in FORBIDDEN_KPROBE_HELPERS:
        if mutator in code:
            reasons.append(
                f"Forbidden kprobe mutator '{mutator}'. Kprobes are "
                "observability only."
            )

    return reasons


def _check_helpers_and_calls(code: str) -> list[str]:
    """Check BPF helper whitelist, printk args, and NULL checks."""
    reasons: list[str] = []
    helper_matches = re.findall(r"\b(bpf_[a-zA-Z0-9_]+)\s*\(", code)
    for helper in helper_matches:
        if helper not in WHITELISTED_HELPERS:
            reasons.append(
                f"Forbidden or non-whitelisted BPF helper: {helper}."
            )

    # Check bpf_printk format arguments (max 3 args beyond format string)
    printk_calls = re.findall(r"bpf_printk\s*\((.*?)\);", code, re.DOTALL)
    for call in printk_calls:
        # Split on commas outside quotes and parens
        args: list[str] = []
        cur: list[str] = []
        in_str = False
        p_depth = 0
        for ch in call:
            if ch == '"':
                in_str = not in_str
                cur.append(ch)
            elif not in_str:
                if ch == "(":
                    p_depth += 1
                    cur.append(ch)
                elif ch == ")":
                    p_depth -= 1
                    cur.append(ch)
                elif ch == "," and p_depth == 0:
                    args.append("".join(cur).strip())
                    cur = []
                else:
                    cur.append(ch)
            else:
                cur.append(ch)
        if cur:
            args.append("".join(cur).strip())
        if len(args) > 4:
            reasons.append(
                f"bpf_printk called with {len(args) - 1} format args "
                "(maximum allowed is 3)."
            )

    # Check NULL check on bpf_map_lookup_elem
    map_lookup_matches = re.finditer(
        r"([a-zA-Z0-9_]+)\s*=\s*(?:\([^)]+\)\s*)?bpf_map_lookup_elem\s*\(",
        code,
    )
    for match in map_lookup_matches:
        var_name = match.group(1)
        subsequent_code = code[match.end() :]
        null_check_pat = (
            rf"if\s*\(\s*(!\s*{var_name}|{var_name}\s*==\s*NULL|"
            rf"NULL\s*==\s*{var_name}|{var_name}\s*==\s*0)\b"
        )
        if not re.search(null_check_pat, subsequent_code):
            reasons.append(
                f"bpf_map_lookup_elem result '{var_name}' dereferenced "
                "without subsequent NULL check."
            )

    # Check NULL check on bpf_ringbuf_reserve
    ringbuf_matches = re.finditer(
        r"([a-zA-Z0-9_]+)\s*=\s*(?:\([^)]+\)\s*)?bpf_ringbuf_reserve\s*\(",
        code,
    )
    for match in ringbuf_matches:
        var_name = match.group(1)
        subsequent_code = code[match.end() :]
        null_check_pat = (
            rf"if\s*\(\s*(!\s*{var_name}|{var_name}\s*==\s*NULL|"
            rf"NULL\s*==\s*{var_name}|{var_name}\s*==\s*0)\b"
        )
        if not re.search(null_check_pat, subsequent_code):
            reasons.append(
                f"bpf_ringbuf_reserve result '{var_name}' dereferenced "
                "without subsequent NULL check."
            )

    return reasons


def _check_disallowed_constructs(code: str) -> list[str]:
    """Check for forbidden keywords, block comments, and loops."""
    reasons: list[str] = []

    if re.search(r"/\*[\s\S]*?\*/", code):
        reasons.append("Block comments /* ... */ are forbidden; use // only.")

    if re.search(r"\bwhile\s*\(", code):
        reasons.append("Forbidden 'while' loop detected.")

    if re.search(r"for\s*\(\s*;\s*;\s*\)", code):
        reasons.append("Forbidden unbounded 'for(;;)' loop detected.")

    if re.search(r"\bgoto\b", code):
        reasons.append("Forbidden 'goto' statement detected.")

    for libc_func in FORBIDDEN_LIBC_CALLS:
        if re.search(rf"\b{libc_func}\s*\(", code):
            reasons.append(f"Forbidden libc function '{libc_func}' called.")

    if re.search(r"\b(float|double)\b", code):
        reasons.append("Floating-point types (float/double) forbidden in BPF.")

    # Check loop bounds and unroll pragma
    for loop_match in re.finditer(r"for\s*\([^;]*;([^;]+);[^)]*\)", code):
        cond = loop_match.group(1)
        bound_match = re.search(r"<\s*([a-zA-Z0-9_]+)", cond)
        if bound_match:
            val_str = bound_match.group(1)
            if val_str.isdigit() and int(val_str) > 32:
                reasons.append(
                    f"Loop bound {val_str} exceeds maximum allowed bound 32."
                )

        # Check for #pragma unroll before the for loop
        prefix = code[: loop_match.start()]
        last_chunk = prefix[-80:]
        if "#pragma unroll" not in last_chunk:
            reasons.append("Loop is missing mandatory '#pragma unroll'.")

    # Local buffer sizes under 256 bytes
    array_matches = re.finditer(
        r"\b(?:char|__u8|__u16|__u32|int)\s+[a-zA-Z0-9_]+\s*\[\s*([0-9]+)\s*\]",
        code,
    )
    for arr in array_matches:
        size = int(arr.group(1))
        if size > 256:
            reasons.append(
                f"Local stack array size {size} exceeds 256 bytes limit."
            )

    return reasons


def _run_clang_compile(code: str) -> list[str]:
    """Optionally verify eBPF compilation with clang if available."""
    clang_path = shutil.which("clang")
    if not clang_path:
        return []
    cmd = [
        clang_path,
        "-target",
        "bpf",
        "-O2",
        "-g",
        "-c",
        "-x",
        "c",
        "-o",
        os.devnull,
        "-",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=code.encode("utf-8"),
            capture_output=True,
            timeout=10,
        )
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace")[:200]
            return [f"Clang BPF verification failed: {err}"]
    except Exception as exc:
        return [f"Clang execution error: {exc}"]
    return []


# ====================================================================
# STATIC VALIDATION GATE
# ====================================================================


def validate_sample(
    intent: str,
    code: str,
    *,
    existing_intents: list[str] | None = None,
    existing_codes: list[str] | None = None,
    clang_check: bool = False,
) -> list[str]:
    """Validate intent and C code against verifier safety rules.

    Returns a list of rejection reasons (empty list = accepted).
    """
    reasons: list[str] = []

    # 1. Syntax, fences, intent length and forbidden tokens
    if not intent or not intent.strip():
        reasons.append("Intent is empty.")
    if not code or not code.strip():
        reasons.append("Code is empty.")

    if "```" in code:
        reasons.append("Code contains markdown fences (```).")

    words = intent.strip().split()
    if len(words) < 8 or len(words) > 60:
        reasons.append(
            f"Intent length of {len(words)} words is outside 8-60 range."
        )

    for forbidden_tok in ("#include", "SEC(", "bpf_"):
        if forbidden_tok in intent:
            reasons.append(
                "Intent contains forbidden technical token: "
                f"'{forbidden_tok}'."
            )

    if reasons:
        return reasons

    # 2. Includes, license, and delimiters
    reasons.extend(_check_includes(code))

    if not re.search(
        r'char\s+LICENSE\[\s*\]\s*SEC\(\s*"license"\s*\)\s*=\s*"GPL"\s*;',
        code,
    ):
        reasons.append(
            'Missing mandatory char LICENSE[] SEC("license") = "GPL";'
        )

    reasons.extend(_check_balanced_delimiters(code))

    # 3. SEC sections
    sec_reasons, prog_sec = _check_sections(code)
    reasons.extend(sec_reasons)

    # 4 & 5. Program type specific checks
    if prog_sec == "xdp":
        reasons.extend(_check_xdp_rules(code))
    elif prog_sec in ("kprobe/__x64_sys_execve", "kprobe/__x64_sys_openat"):
        reasons.extend(_check_kprobe_rules(code))

    # 6. Helpers, printk, NULL checks
    reasons.extend(_check_helpers_and_calls(code))

    # 7. Disallowed constructs
    reasons.extend(_check_disallowed_constructs(code))

    # 8. Deduplication against existing records
    if existing_intents:
        norm_i = normalize_intent(intent)
        curr_i_hash = hashlib.sha256(norm_i.encode("utf-8")).hexdigest()
        for prior_intent in existing_intents:
            prior_norm = normalize_intent(prior_intent)
            prior_hash = hashlib.sha256(prior_norm.encode("utf-8")).hexdigest()
            if curr_i_hash == prior_hash:
                reasons.append("Duplicate normalized intent detected.")
                break
            sim = jaccard_similarity(intent, prior_intent)
            if sim > 0.85:
                reasons.append(
                    f"Intent token Jaccard similarity {sim:.2f} > 0.85 "
                    "threshold."
                )
                break

    if existing_codes:
        norm_c = normalize_code(code)
        curr_c_hash = hashlib.sha256(norm_c.encode("utf-8")).hexdigest()
        for prior_code in existing_codes:
            prior_norm = normalize_code(prior_code)
            prior_hash = hashlib.sha256(prior_norm.encode("utf-8")).hexdigest()
            if curr_c_hash == prior_hash:
                reasons.append("Duplicate normalized code detected.")
                break

    # Optional clang verification
    if clang_check:
        reasons.extend(_run_clang_compile(code))

    return reasons


# ====================================================================
# DIVERSITY ENGINE
# ====================================================================


def scale_quotas(total_rows: int) -> dict[str, int]:
    """Scale category quotas proportionally for any target row count."""
    if total_rows == 300:
        return dict(CATEGORY_BASE_QUOTAS)

    scaled: dict[str, int] = {}
    xdp_keys = [f"X{i}" for i in range(1, 10)]
    kprobe_keys = [f"K{i}" for i in range(1, 6)]

    target_xdp = round(total_rows * 0.60)
    target_kprobe = total_rows - target_xdp

    # Scale XDP
    xdp_sum = sum(CATEGORY_BASE_QUOTAS[k] for k in xdp_keys)
    xdp_alloc = 0
    for k in xdp_keys:
        cnt = round(CATEGORY_BASE_QUOTAS[k] * target_xdp / xdp_sum)
        scaled[k] = cnt
        xdp_alloc += cnt
    # Balance discrepancy on largest XDP category
    scaled["X1"] += target_xdp - xdp_alloc

    # Scale kprobe
    kp_sum = sum(CATEGORY_BASE_QUOTAS[k] for k in kprobe_keys)
    kp_alloc = 0
    for k in kprobe_keys:
        cnt = round(CATEGORY_BASE_QUOTAS[k] * target_kprobe / kp_sum)
        scaled[k] = cnt
        kp_alloc += cnt
    # Balance discrepancy on largest kprobe category
    scaled["K1"] += target_kprobe - kp_alloc

    return scaled


def _generate_unique_params(
    category: str,
    rng: random.Random,
    seen_params: set[tuple[Any, ...]],
) -> dict[str, Any]:
    """Generate unique concrete parameters for a given category."""
    rfc5737_nets = [
        (192, 0, 2),
        (198, 51, 100),
        (203, 0, 113),
    ]
    rfc1918_nets = [
        (10, rng.randint(0, 255), rng.randint(1, 254)),
        (172, rng.randint(16, 31), rng.randint(1, 254)),
        (192, 168, rng.randint(1, 254)),
    ]
    public_nets = [
        (198, 18, rng.randint(1, 254)),
        (203, 178, rng.randint(1, 254)),
        (45, 33, rng.randint(1, 254)),
    ]
    all_nets = rfc5737_nets + rfc1918_nets + public_nets

    service_ports = [80, 443, 22, 53, 123, 11211, 1900, 3306, 5432, 8080]
    paths = [
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/root/.ssh/authorized_keys",
        "/etc/ssh/sshd_config",
        "/etc/security/opasswd",
    ]
    suspicious_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    comms = ["curl", "wget", "nc", "python", "bash", "ssh", "nmap", "miner"]
    uids = [0, 1000, 1001, 1002, 33, 65534, 105]

    for _ in range(10000):
        net = rng.choice(all_nets)
        host = rng.randint(2, 254)
        ip_str = f"{net[0]}.{net[1]}.{net[2]}.{host}"
        ip_int = (net[0] << 24) | (net[1] << 16) | (net[2] << 8) | host
        ip_hex = f"0x{ip_int:08X}"

        params: dict[str, Any] = {}
        if category == "X1":
            params = {"ip": ip_str, "ip_hex": ip_hex}
        elif category == "X2":
            cidr_mask = rng.choice([16, 24, 28])
            mask_val = (0xFFFFFFFF << (32 - cidr_mask)) & 0xFFFFFFFF
            net_val = ip_int & mask_val
            params = {
                "subnet": f"{ip_str}/{cidr_mask}",
                "mask_hex": f"0x{mask_val:08X}",
                "net_hex": f"0x{net_val:08X}",
                "cidr": cidr_mask,
            }
        elif category == "X3":
            port = rng.choice(service_ports + [rng.randint(1024, 65535)])
            params = {"port": port, "proto": "TCP"}
        elif category == "X4":
            port = rng.choice(
                [53, 67, 123, 161, 514, rng.randint(1024, 65535)]
            )
            params = {"port": port, "proto": "UDP"}
        elif category == "X5":
            thresh = rng.choice([100, 250, 500, 1000, 2000, 5000, 10000])
            params = {"threshold": thresh, "service": "SYN-flood"}
        elif category == "X6":
            ampl_port = rng.choice([53, 123, 11211, 1900])
            params = {"source_port": ampl_port, "service": "UDP-reflection"}
        elif category == "X7":
            params = {"protocol": "ICMP", "type": "echo-request"}
        elif category == "X8":
            params = {"allowed_ip": ip_str, "allowed_ip_hex": ip_hex}
        elif category == "X9":
            params = {"feature": "IPv4-fragments"}
        elif category == "K1":
            params = {"syscall": "sys_execve", "scope": "host-wide"}
        elif category == "K2":
            path = rng.choice(paths)
            params = {"syscall": "sys_openat", "path": path}
        elif category == "K3":
            uid = rng.choice(uids)
            comm = rng.choice(comms)
            params = {"uid": uid, "comm": comm}
        elif category == "K4":
            params = {"syscall": "sys_execve", "metric": "count_per_pid"}
        elif category == "K5":
            sdir = rng.choice(suspicious_dirs)
            params = {"suspicious_dir": sdir}

        p_tuple = tuple(sorted(params.items()))
        if p_tuple not in seen_params:
            seen_params.add(p_tuple)
            return params

    return params


def generate_job_specs(total_rows: int, seed: int) -> list[JobSpec]:
    """Generate deterministic job specs matching quotas and categories."""
    rng = random.Random(seed)
    quotas = scale_quotas(total_rows)

    styles = [
        "terse-imperative",
        "soc-ticket",
        "incident-response-urgent",
        "plain-english-non-expert",
        "compliance-auditor",
        "devops-runbook",
    ]

    specs: list[JobSpec] = []
    job_idx = 1
    seen_params_by_cat: dict[str, set[tuple[Any, ...]]] = {
        cat: set() for cat in quotas
    }

    for cat, count in quotas.items():
        for i in range(count):
            job_id = f"job_{job_idx:04d}"
            job_idx += 1

            # Distribute tiers roughly 40/40/20
            tier_r = i % 10
            if tier_r < 4:
                tier = "basic"
            elif tier_r < 8:
                tier = "intermediate"
            else:
                tier = "advanced"

            style = styles[i % len(styles)]
            hook_mention = "explicit" if (i % 2 == 0) else "implicit"
            params = _generate_unique_params(cat, rng, seen_params_by_cat[cat])

            specs.append(
                JobSpec(
                    job_id=job_id,
                    category=cat,
                    tier=tier,
                    style=style,
                    hook_mention=hook_mention,
                    params=params,
                )
            )

    return specs


# ====================================================================
# OFFLINE DRY-RUN GENERATOR
# ====================================================================


def generate_dry_run_sample(spec: JobSpec) -> tuple[str, str]:
    """Generate verifier-safe intent and C code offline for --dry-run."""
    p = spec.params
    hook = "XDP hook" if spec.hook_mention == "explicit" else "network driver"
    k_hook = "kprobe" if spec.hook_mention == "explicit" else "syscall trace"

    intents_by_style: dict[str, str] = {
        "terse-imperative": (
            f"Drop incoming network packets matching {p} "
            f"immediately using {hook}."
        ),
        "soc-ticket": (
            f"Security Ticket SEC-{spec.job_id[4:]}: Filter hostile network "
            f"traffic matching parameter set {p} via {hook}."
        ),
        "incident-response-urgent": (
            f"URGENT INCIDENT ALERT: Immediately isolate host and drop "
            f"traffic for {p} at {hook} level."
        ),
        "plain-english-non-expert": (
            f"Please write a kernel safety program to prevent incoming "
            f"connections from {p} before they reach the stack."
        ),
        "compliance-auditor": (
            f"Compliance Mandate SEC-AUDIT: Restrict packet flow and filter "
            f"{p} in accordance with firewall policies."
        ),
        "devops-runbook": (
            f"Infrastructure Runbook Step {spec.job_id[4:]}: Enforce packet "
            f"filtering rule for {p} to safeguard host."
        ),
    }

    intent = intents_by_style.get(
        spec.style,
        f"Filter traffic for parameters {p} at the ingress boundary.",
    )

    # Common code blocks
    xdp_prologue = (
        "    void *data = (void *)(long)ctx->data;\n"
        "    void *data_end = (void *)(long)ctx->data_end;\n\n"
        "    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > "
        "data_end)\n"
        "        return XDP_PASS;\n\n"
        "    struct ethhdr *eth = data;\n"
        "    if (eth->h_proto != bpf_htons(ETH_P_IP))\n"
        "        return XDP_PASS;\n\n"
        "    struct iphdr *ip = data + sizeof(struct ethhdr);\n"
    )

    xdp_hdrs = (
        "#include <uapi/linux/bpf.h>\n"
        "#include <linux/in.h>\n"
        "#include <linux/if_ether.h>\n"
        "#include <linux/ip.h>\n"
        "#include <bpf/bpf_helpers.h>\n"
        "#include <bpf/bpf_endian.h>\n\n"
    )

    kprobe_hdrs = (
        "#include <uapi/linux/bpf.h>\n"
        "#include <linux/in.h>\n"
        "#include <linux/if_ether.h>\n"
        "#include <linux/ip.h>\n"
        "#include <linux/ptrace.h>\n"
        "#define __TARGET_ARCH_x86\n"
        "#include <bpf/bpf_helpers.h>\n"
        "#include <bpf/bpf_tracing.h>\n\n"
    )

    c_code = ""
    cat = spec.category

    if cat == "X1":
        ip_hex = p.get("ip_hex", "0xCB007132")
        ip_str = p.get("ip", "203.0.113.50")
        intent = (
            f"Drop all incoming network packets from source address {ip_str} "
            f"at the earliest {hook} point."
        )
        c_code = (
            f"{xdp_hdrs}"
            'SEC("xdp")\n'
            f"int xdp_drop_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            f"    if (ip->saddr == bpf_htonl({ip_hex}))\n"
            "        return XDP_DROP;\n\n"
            "    return XDP_PASS;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X2":
        net_hex = p.get("net_hex", "0xC0000200")
        mask_hex = p.get("mask_hex", "0xFFFFFF00")
        subnet = p.get("subnet", "192.0.2.0/24")
        intent = (
            f"Filter and drop incoming traffic originating from subnet "
            f"{subnet} at the {hook}."
        )
        c_code = (
            f"{xdp_hdrs}"
            'SEC("xdp")\n'
            f"int xdp_drop_subnet_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            f"    if ((bpf_ntohl(ip->saddr) & {mask_hex}) == {net_hex})\n"
            "        return XDP_DROP;\n\n"
            "    return XDP_PASS;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X3":
        port = p.get("port", 8080)
        intent = (
            f"Block and drop all inbound TCP traffic destined for port "
            f"{port} at the {hook} level."
        )
        c_code = (
            "#include <uapi/linux/bpf.h>\n"
            "#include <linux/in.h>\n"
            "#include <linux/if_ether.h>\n"
            "#include <linux/ip.h>\n"
            "#include <linux/tcp.h>\n"
            "#include <bpf/bpf_helpers.h>\n"
            "#include <bpf/bpf_endian.h>\n\n"
            'SEC("xdp")\n'
            f"int xdp_drop_tcp_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            "    if (ip->protocol != IPPROTO_TCP)\n"
            "        return XDP_PASS;\n\n"
            "    __u32 ihl = ip->ihl * 4;\n"
            "    if (ihl < sizeof(struct iphdr))\n"
            "        return XDP_PASS;\n\n"
            "    struct tcphdr *tcp = (void *)ip + ihl;\n"
            "    if ((void *)(tcp + 1) > data_end)\n"
            "        return XDP_PASS;\n\n"
            f"    if (tcp->dest == bpf_htons({port}))\n"
            "        return XDP_DROP;\n\n"
            "    return XDP_PASS;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X4":
        port = p.get("port", 5353)
        intent = (
            f"Reject and discard all incoming UDP datagrams targeting port "
            f"{port} via {hook}."
        )
        c_code = (
            "#include <uapi/linux/bpf.h>\n"
            "#include <linux/in.h>\n"
            "#include <linux/if_ether.h>\n"
            "#include <linux/ip.h>\n"
            "#include <linux/udp.h>\n"
            "#include <bpf/bpf_helpers.h>\n"
            "#include <bpf/bpf_endian.h>\n\n"
            'SEC("xdp")\n'
            f"int xdp_drop_udp_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            "    if (ip->protocol != IPPROTO_UDP)\n"
            "        return XDP_PASS;\n\n"
            "    __u32 ihl = ip->ihl * 4;\n"
            "    if (ihl < sizeof(struct iphdr))\n"
            "        return XDP_PASS;\n\n"
            "    struct udphdr *udp = (void *)ip + ihl;\n"
            "    if ((void *)(udp + 1) > data_end)\n"
            "        return XDP_PASS;\n\n"
            f"    if (udp->dest == bpf_htons({port}))\n"
            "        return XDP_DROP;\n\n"
            "    return XDP_PASS;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X5":
        thresh = p.get("threshold", 1000)
        intent = (
            f"Mitigate SYN floods by tracking source counts in an LRU map and "
            f"dropping over threshold {thresh}."
        )
        c_code = (
            "#include <uapi/linux/bpf.h>\n"
            "#include <linux/in.h>\n"
            "#include <linux/if_ether.h>\n"
            "#include <linux/ip.h>\n"
            "#include <linux/tcp.h>\n"
            "#include <bpf/bpf_helpers.h>\n"
            "#include <bpf/bpf_endian.h>\n\n"
            "struct {\n"
            "    __uint(type, BPF_MAP_TYPE_LRU_HASH);\n"
            "    __uint(max_entries, 10240);\n"
            "    __type(key, __u32);\n"
            "    __type(value, __u64);\n"
            f'}} syn_map_{spec.job_id} SEC(".maps");\n\n'
            'SEC("xdp")\n'
            f"int xdp_syn_mitigate_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            "    if (ip->protocol != IPPROTO_TCP)\n"
            "        return XDP_PASS;\n\n"
            "    __u32 ihl = ip->ihl * 4;\n"
            "    if (ihl < sizeof(struct iphdr))\n"
            "        return XDP_PASS;\n\n"
            "    struct tcphdr *tcp = (void *)ip + ihl;\n"
            "    if ((void *)(tcp + 1) > data_end)\n"
            "        return XDP_PASS;\n\n"
            "    if (!tcp->syn || tcp->ack)\n"
            "        return XDP_PASS;\n\n"
            "    __u32 src_ip = ip->saddr;\n"
            f"    __u64 *cnt = bpf_map_lookup_elem(&syn_map_{spec.job_id}, "
            "&src_ip);\n"
            "    if (!cnt) {\n"
            "        __u64 init_cnt = 1;\n"
            f"        bpf_map_update_elem(&syn_map_{spec.job_id}, &src_ip, "
            "&init_cnt, BPF_ANY);\n"
            "        return XDP_PASS;\n"
            "    }\n\n"
            "    __sync_fetch_and_add(cnt, 1);\n"
            f"    if (*cnt > {thresh})\n"
            "        return XDP_DROP;\n\n"
            "    return XDP_PASS;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X6":
        sport = p.get("source_port", 53)
        intent = (
            f"Defend against reflection amplification by dropping inbound UDP "
            f"packets from source port {sport} at {hook}."
        )
        c_code = (
            "#include <uapi/linux/bpf.h>\n"
            "#include <linux/in.h>\n"
            "#include <linux/if_ether.h>\n"
            "#include <linux/ip.h>\n"
            "#include <linux/udp.h>\n"
            "#include <bpf/bpf_helpers.h>\n"
            "#include <bpf/bpf_endian.h>\n\n"
            'SEC("xdp")\n'
            f"int xdp_drop_amplification_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            "    if (ip->protocol != IPPROTO_UDP)\n"
            "        return XDP_PASS;\n\n"
            "    __u32 ihl = ip->ihl * 4;\n"
            "    if (ihl < sizeof(struct iphdr))\n"
            "        return XDP_PASS;\n\n"
            "    struct udphdr *udp = (void *)ip + ihl;\n"
            "    if ((void *)(udp + 1) > data_end)\n"
            "        return XDP_PASS;\n\n"
            f"    if (udp->source == bpf_htons({sport}))\n"
            "        return XDP_DROP;\n\n"
            "    return XDP_PASS;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X7":
        intent = (
            f"[{spec.job_id}] Protect host from network reconnaissance by "
            f"dropping all ICMP ping echo requests at {hook} layer "
            f"({spec.tier})."
        )
        c_code = (
            "#include <uapi/linux/bpf.h>\n"
            "#include <linux/in.h>\n"
            "#include <linux/if_ether.h>\n"
            "#include <linux/ip.h>\n"
            "#include <linux/icmp.h>\n"
            "#include <bpf/bpf_helpers.h>\n"
            "#include <bpf/bpf_endian.h>\n\n"
            'SEC("xdp")\n'
            f"int xdp_block_icmp_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            "    if (ip->protocol != IPPROTO_ICMP)\n"
            "        return XDP_PASS;\n\n"
            "    __u32 ihl = ip->ihl * 4;\n"
            "    if (ihl < sizeof(struct iphdr))\n"
            "        return XDP_PASS;\n\n"
            "    struct icmphdr *icmp = (void *)ip + ihl;\n"
            "    if ((void *)(icmp + 1) > data_end)\n"
            "        return XDP_PASS;\n\n"
            "    return XDP_DROP;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X8":
        aip_hex = p.get("allowed_ip_hex", "0xC0A8010A")
        aip = p.get("allowed_ip", "192.168.1.10")
        intent = (
            f"Enforce strict default-drop network security policy allowing "
            f"only inbound IP {aip} at {hook}."
        )
        c_code = (
            f"{xdp_hdrs}"
            'SEC("xdp")\n'
            f"int xdp_allowlist_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            f"    if (ip->saddr == bpf_htonl({aip_hex}))\n"
            "        return XDP_PASS;\n\n"
            "    return XDP_DROP;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "X9":
        intent = (
            f"[{spec.job_id}] Harden network perimeter against evasion by "
            f"dropping all fragmented IPv4 packets using {hook} "
            f"({spec.tier})."
        )
        c_code = (
            f"{xdp_hdrs}"
            'SEC("xdp")\n'
            f"int xdp_drop_frags_{spec.job_id}(struct xdp_md *ctx)\n"
            "{\n"
            f"{xdp_prologue}"
            "    if (bpf_ntohs(ip->frag_off) & 0x3FFF)\n"
            "        return XDP_DROP;\n\n"
            "    return XDP_PASS;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "K1":
        intent = (
            f"[{spec.job_id}] Audit and log host execution events including "
            f"process identifier and command line via {k_hook} ({spec.tier})."
        )
        c_code = (
            f"{kprobe_hdrs}"
            "#define COMM_LEN 16\n"
            "#define PATH_LEN 128\n\n"
            'SEC("kprobe/__x64_sys_execve")\n'
            f"int trace_exec_{spec.job_id}(struct pt_regs *ctx)\n"
            "{\n"
            "    struct pt_regs *sregs = "
            "(struct pt_regs *)PT_REGS_PARM1(ctx);\n"
            "    const char *filename_ptr = NULL;\n"
            "    char filename[PATH_LEN] = {};\n"
            "    char comm[COMM_LEN] = {};\n"
            "    __u32 pid = bpf_get_current_pid_tgid() >> 32;\n\n"
            "    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr),\n"
            "                          &PT_REGS_PARM1(sregs));\n"
            "    bpf_probe_read_user_str(filename, sizeof(filename), "
            "filename_ptr);\n"
            "    bpf_get_current_comm(comm, sizeof(comm));\n"
            '    bpf_printk("execve pid=%d comm=%s file=%s", '
            "pid, comm, filename);\n"
            "    return 0;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "K2":
        path = p.get("path", "/etc/shadow")
        intent = (
            "Monitor filesystem integrity and alert on openat calls "
            f"targeting critical file {path} using {k_hook}."
        )
        c_code = (
            f"{kprobe_hdrs}"
            "#define PATH_LEN 64\n\n"
            'SEC("kprobe/__x64_sys_openat")\n'
            f"int trace_openat_{spec.job_id}(struct pt_regs *ctx)\n"
            "{\n"
            "    struct pt_regs *sregs = "
            "(struct pt_regs *)PT_REGS_PARM1(ctx);\n"
            "    const char *filename_ptr = NULL;\n"
            "    char path[PATH_LEN] = {};\n"
            f'    static const char target[] = "{path}";\n'
            "    int match = 1;\n\n"
            "    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr),\n"
            "                          &PT_REGS_PARM2(sregs));\n"
            "    bpf_probe_read_user_str(path, sizeof(path), "
            "filename_ptr);\n\n"
            "    #pragma unroll\n"
            f"    for (int i = 0; i < {min(len(path), 32)}; i++) {{\n"
            "        if (path[i] != target[i]) {\n"
            "            match = 0;\n"
            "            break;\n"
            "        }\n"
            "    }\n\n"
            "    if (match) {\n"
            "        __u32 pid = bpf_get_current_pid_tgid() >> 32;\n"
            '        bpf_printk("openat sensitive target hit by pid=%d", '
            "pid);\n"
            "    }\n"
            "    return 0;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "K3":
        uid = p.get("uid", 1000)
        comm = p.get("comm", "curl")
        intent = (
            f"Filter process execution events by verifying caller user "
            f"identifier {uid} and command {comm} with {k_hook}."
        )
        c_code = (
            f"{kprobe_hdrs}"
            "#define COMM_LEN 16\n\n"
            'SEC("kprobe/__x64_sys_execve")\n'
            f"int filter_exec_{spec.job_id}(struct pt_regs *ctx)\n"
            "{\n"
            "    __u64 uid_gid = bpf_get_current_uid_gid();\n"
            "    __u32 uid = (__u32)uid_gid;\n\n"
            f"    if (uid == {uid}) {{\n"
            "        char comm[COMM_LEN] = {};\n"
            "        __u32 pid = bpf_get_current_pid_tgid() >> 32;\n"
            "        bpf_get_current_comm(comm, sizeof(comm));\n"
            '        bpf_printk("execve match uid=%d pid=%d comm=%s", '
            "uid, pid, comm);\n"
            "    }\n"
            "    return 0;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "K4":
        intent = (
            f"[{spec.job_id}] Record per-process syscall invocations in a "
            f"kernel hash map for behavioral profiling using {k_hook} "
            f"({spec.tier})."
        )
        c_code = (
            f"{kprobe_hdrs}"
            "struct {\n"
            "    __uint(type, BPF_MAP_TYPE_HASH);\n"
            "    __uint(max_entries, 10240);\n"
            "    __type(key, __u32);\n"
            "    __type(value, __u64);\n"
            f'}} counts_{spec.job_id} SEC(".maps");\n\n'
            'SEC("kprobe/__x64_sys_execve")\n'
            f"int count_calls_{spec.job_id}(struct pt_regs *ctx)\n"
            "{\n"
            "    __u32 pid = bpf_get_current_pid_tgid() >> 32;\n"
            "    __u64 *val = "
            f"bpf_map_lookup_elem(&counts_{spec.job_id}, &pid);\n"
            "    if (!val) {\n"
            "        __u64 init_cnt = 1;\n"
            "        bpf_map_update_elem("
            f"&counts_{spec.job_id}, &pid, &init_cnt, BPF_ANY);\n"
            "        return 0;\n"
            "    }\n"
            "    __sync_fetch_and_add(val, 1);\n"
            '    bpf_printk("syscall count updated for pid=%d", pid);\n'
            "    return 0;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    elif cat == "K5":
        sdir = p.get("suspicious_dir", "/tmp")
        intent = (
            f"Detect malware execution attempts by monitoring execve calls "
            f"from suspicious directory {sdir} via {k_hook}."
        )
        c_code = (
            f"{kprobe_hdrs}"
            "#define PATH_LEN 64\n\n"
            'SEC("kprobe/__x64_sys_execve")\n'
            f"int detect_suspicious_{spec.job_id}(struct pt_regs *ctx)\n"
            "{\n"
            "    struct pt_regs *sregs = "
            "(struct pt_regs *)PT_REGS_PARM1(ctx);\n"
            "    const char *filename_ptr = NULL;\n"
            "    char path[PATH_LEN] = {};\n"
            f'    static const char prefix[] = "{sdir}/";\n'
            "    int is_match = 1;\n\n"
            "    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr),\n"
            "                          &PT_REGS_PARM1(sregs));\n"
            "    bpf_probe_read_user_str(path, sizeof(path), "
            "filename_ptr);\n\n"
            "    #pragma unroll\n"
            f"    for (int i = 0; i < {min(len(sdir) + 1, 32)}; i++) {{\n"
            "        if (path[i] != prefix[i]) {\n"
            "            is_match = 0;\n"
            "            break;\n"
            "        }\n"
            "    }\n\n"
            "    if (is_match) {\n"
            "        __u32 pid = bpf_get_current_pid_tgid() >> 32;\n"
            '        bpf_printk("suspicious exec from dir pid=%d", pid);\n'
            "    }\n"
            "    return 0;\n"
            "}\n\n"
            'char LICENSE[] SEC("license") = "GPL";\n'
        )

    return intent, c_code


# ====================================================================
# GEMINI REST API CLIENT
# ====================================================================


def build_gemini_payload(
    spec: JobSpec,
    rejections: list[str] | None = None,
) -> dict[str, Any]:
    """Build the JSON body for Gemini models:generateContent REST endpoint."""
    system_instruction = (
        f"{GENERATOR_RULEBOOK}\n\nGOLD EXEMPLARS:\n{GOLD_EXEMPLARS}"
    )

    spec_dict = {
        "job_id": spec.job_id,
        "category": spec.category,
        "tier": spec.tier,
        "style": spec.style,
        "hook_mention": spec.hook_mention,
        "params": spec.params,
    }

    user_text = (
        f"Job Specification: {json.dumps(spec_dict)}\n"
        "Produce one training example for this spec. Frame it as "
        "defensive security engineering."
    )
    if rejections:
        rejection_summary = "; ".join(rejections)
        user_text += (
            f"\n\nPrevious attempt rejected: {rejection_summary}; "
            "fix these precisely."
        )

    return {
        "systemInstruction": {
            "parts": [{"text": system_instruction}],
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": user_text}],
            }
        ],
        "generationConfig": {
            "temperature": 0.8,
            "topP": 0.95,
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": {
                    "intent": {"type": "STRING"},
                    "code": {"type": "STRING"},
                },
                "required": ["intent", "code"],
            },
            "thinkingConfig": {
                "thinkingBudget": 1024,
            },
        },
        "safetySettings": [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_ONLY_HIGH",
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_ONLY_HIGH",
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_ONLY_HIGH",
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_ONLY_HIGH",
            },
        ],
    }


# ====================================================================
# ENGINE CORE & ASYNC WORKERS
# ====================================================================


def _make_console() -> Console:
    """Return a Rich Console safe for Windows legacy terminals.

    On Windows the default stdout encoding is cp1252, which cannot
    represent the braille spinner characters Rich uses (U+280B etc.).
    We wrap the raw stdout binary buffer with a UTF-8 TextIOWrapper so
    Rich writes UTF-8 bytes directly, bypassing the cp1252 codec.
    ``legacy_windows=False`` disables Rich's own Windows shim so it
    renders ANSI sequences instead of the legacy Win32 API path.
    ``force_terminal=True`` preserves colour/markup when stdout is
    redirected (e.g. CI log capture).
    """
    if hasattr(sys.stdout, "buffer"):
        utf8_stream: io.TextIOWrapper = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
    else:
        utf8_stream = sys.stdout  # type: ignore[assignment]
    return Console(
        file=utf8_stream,
        legacy_windows=False,
        force_terminal=True,
    )


class DatasetEngine:
    """Async engine managing generation, validation, state, and Rich UI."""

    def __init__(
        self,
        rows: int = 300,
        output_path: str = "kernelgemma_dataset.jsonl",
        model: str = "gemini-2.5-flash",
        concurrency: int = 8,
        seed: int = 42,
        resume: bool = False,
        clang_check: bool = False,
        dry_run: bool = False,
    ) -> None:
        self.total_rows = rows
        self.output_path = output_path
        self.manifest_path = f"{output_path}.meta.jsonl"
        self.model = model
        self.concurrency = concurrency
        self.seed = seed
        self.resume = resume
        self.clang_check = clang_check
        self.dry_run = dry_run

        self.api_key = os.environ.get("GEMINI_API_KEY", "")
        self.api_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )

        self.quotas = scale_quotas(self.total_rows)
        self.specs = generate_job_specs(self.total_rows, self.seed)

        self.lock = asyncio.Lock()
        self.cooldown_event = asyncio.Event()
        self.cooldown_event.set()

        self.accepted_rows: list[AcceptedRow] = []
        self.existing_intents: list[str] = []
        self.existing_codes: list[str] = []

        self.completed_job_ids: set[str] = set()
        self.total_attempts = 0
        self.total_rejections = 0
        self.total_api_calls = 0
        self.total_retries = 0
        self.total_429s = 0
        self.latencies: list[float] = []

        self.cat_accepted: dict[str, int] = {k: 0 for k in self.quotas}
        self.cat_rejected: dict[str, int] = {k: 0 for k in self.quotas}
        self.cat_inflight: dict[str, int] = {k: 0 for k in self.quotas}

        self.recent_events: list[str] = []
        self.start_time = time.time()
        self.cooldown_remaining = 0.0

        # Output handles
        self._dataset_fp: Any = None
        self._manifest_fp: Any = None

    def log_event(self, msg: str) -> None:
        """Add rolling event for the Rich UI."""
        timestamp = time.strftime("%H:%M:%S")
        self.recent_events.append(f"[{timestamp}] {msg}")
        if len(self.recent_events) > 5:
            self.recent_events.pop(0)

    def load_existing_manifest(self) -> None:
        """Load accepted rows and hashes from manifest if resuming."""
        if not self.resume or not os.path.exists(self.manifest_path):
            return

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    meta = json.loads(line)
                    jid = meta["job_id"]
                    cat = meta["category"]
                    self.completed_job_ids.add(jid)
                    self.cat_accepted[cat] = self.cat_accepted.get(cat, 0) + 1
                except Exception:
                    continue

        if os.path.exists(self.output_path):
            with open(self.output_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        intent = record["messages"][1]["content"]
                        code = record["messages"][2]["content"]
                        self.existing_intents.append(intent)
                        self.existing_codes.append(code)
                    except Exception:
                        continue

    async def _write_accepted_row(self, row: AcceptedRow) -> None:
        """Atomically append accepted row to dataset and manifest."""
        async with self.lock:
            self.accepted_rows.append(row)
            self.existing_intents.append(row.intent)
            self.existing_codes.append(row.code)
            self.completed_job_ids.add(row.job_id)
            self.cat_accepted[row.category] += 1
            self.cat_inflight[row.category] -= 1

            # Exact byte-level schema
            row_dict = {
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": row.intent},
                    {"role": "assistant", "content": row.code},
                ]
            }
            dataset_line = json.dumps(row_dict, ensure_ascii=False) + "\n"
            self._dataset_fp.write(dataset_line)

            manifest_dict = {
                "job_id": row.job_id,
                "category": row.category,
                "intent_hash": row.intent_hash,
                "code_hash": row.code_hash,
                "tier": row.tier,
                "style": row.style,
                "params": row.params,
                "timestamp": row.timestamp,
            }
            manifest_line = (
                json.dumps(manifest_dict, ensure_ascii=False) + "\n"
            )
            self._manifest_fp.write(manifest_line)

            if len(self.accepted_rows) % 10 == 0:
                self._dataset_fp.flush()
                os.fsync(self._dataset_fp.fileno())
                self._manifest_fp.flush()
                os.fsync(self._manifest_fp.fileno())

    async def _call_gemini_api(
        self,
        session: aiohttp.ClientSession,
        payload: dict[str, Any],
    ) -> tuple[str, str]:
        """Make HTTP POST to Gemini REST API with retries and rate limit."""
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }

        max_retries = 6
        for attempt in range(max_retries):
            await self.cooldown_event.wait()
            t0 = time.time()
            self.total_api_calls += 1

            try:
                async with session.post(
                    self.api_url,
                    headers=headers,
                    json=payload,
                ) as resp:
                    latency = (time.time() - t0) * 1000.0
                    self.latencies.append(latency)

                    if resp.status == 200:
                        data = await resp.json()
                        candidates = data.get("candidates", [])
                        if not candidates:
                            block_reason = data.get("promptFeedback", {}).get(
                                "blockReason"
                            )
                            raise aiohttp.ClientError(
                                f"Empty candidates: blockReason={block_reason}"
                            )
                        c0 = candidates[0]
                        finish_reason = c0.get("finishReason")
                        if finish_reason in ("MAX_TOKENS", "SAFETY"):
                            raise aiohttp.ClientError(
                                f"Retryable finishReason: {finish_reason}"
                            )
                        parts = c0.get("content", {}).get("parts", [])
                        if not parts:
                            raise aiohttp.ClientError("Empty candidate parts")
                        raw_text = parts[0].get("text", "")
                        parsed = json.loads(raw_text)
                        return parsed["intent"], parsed["code"]

                    if resp.status == 429:
                        self.total_429s += 1
                        self.total_retries += 1
                        retry_after = resp.headers.get("Retry-After")
                        cooldown_secs = (
                            float(retry_after)
                            if (retry_after and retry_after.isdigit())
                            else 15.0
                        )
                        self.cooldown_event.clear()
                        self.cooldown_remaining = cooldown_secs
                        self.log_event(
                            "HTTP 429 hit. Workers cooling down for "
                            f"{cooldown_secs}s."
                        )
                        await asyncio.sleep(cooldown_secs)
                        self.cooldown_remaining = 0.0
                        self.cooldown_event.set()
                        continue

                    if resp.status in (400, 401, 403, 404):
                        err_body = await resp.text()
                        raise RuntimeError(
                            f"Fatal API error HTTP {resp.status}: {err_body}"
                        )

                    if resp.status in (500, 502, 503, 504):
                        self.total_retries += 1
                        delay = min(60.0, (2**attempt)) * random.uniform(
                            0.5, 1.0
                        )
                        await asyncio.sleep(delay)
                        continue

                    err_text = await resp.text()
                    raise aiohttp.ClientError(
                        f"Unexpected HTTP {resp.status}: {err_text}"
                    )

            except (
                aiohttp.ClientError,
                asyncio.TimeoutError,
                json.JSONDecodeError,
                KeyError,
            ) as exc:
                self.total_retries += 1
                if attempt == max_retries - 1:
                    raise exc
                delay = min(60.0, (2**attempt)) * random.uniform(0.5, 1.0)
                await asyncio.sleep(delay)

        raise RuntimeError("Exceeded maximum API retries.")

    async def _process_job(
        self,
        spec: JobSpec,
        session: aiohttp.ClientSession | None,
        semaphore: asyncio.Semaphore,
    ) -> None:
        """Process a single JobSpec with up to 3 repair attempts."""
        if spec.job_id in self.completed_job_ids:
            return

        async with semaphore:
            self.cat_inflight[spec.category] += 1
            rejections: list[str] = []

            for attempt in range(4):
                if len(self.accepted_rows) >= self.total_rows:
                    self.cat_inflight[spec.category] -= 1
                    return

                self.total_attempts += 1
                if self.total_attempts > self.total_rows * 4:
                    self.cat_inflight[spec.category] -= 1
                    return

                try:
                    if self.dry_run:
                        raw_intent, raw_code = generate_dry_run_sample(spec)
                    else:
                        assert session is not None
                        payload = build_gemini_payload(spec, rejections)
                        raw_intent, raw_code = await self._call_gemini_api(
                            session, payload
                        )
                except Exception as exc:
                    self.total_rejections += 1
                    self.cat_rejected[spec.category] += 1
                    rejections = [f"Generation failed: {exc}"]
                    self.log_event(f"FAIL {spec.job_id}: {exc}")
                    continue

                # Format code: strip fences, ensure single trailing newline
                clean_code = raw_code.strip()
                if clean_code.startswith("```"):
                    clean_code = re.sub(r"^```[a-zA-Z]*\n", "", clean_code)
                    clean_code = re.sub(r"\n```$", "", clean_code).strip()
                clean_code += "\n"

                clean_intent = raw_intent.strip().strip('"').strip("'")

                # Validate
                reasons = validate_sample(
                    clean_intent,
                    clean_code,
                    existing_intents=self.existing_intents,
                    existing_codes=self.existing_codes,
                    clang_check=self.clang_check,
                )

                if not reasons:
                    # Accepted
                    accepted_row = AcceptedRow(
                        job_id=spec.job_id,
                        category=spec.category,
                        intent=clean_intent,
                        code=clean_code,
                        intent_hash=compute_intent_hash(clean_intent),
                        code_hash=compute_code_hash(clean_code),
                        params=spec.params,
                        tier=spec.tier,
                        style=spec.style,
                        timestamp=time.time(),
                    )
                    await self._write_accepted_row(accepted_row)
                    self.log_event(
                        f"ACCEPT {spec.job_id} ({spec.category}) "
                        f"[{len(clean_intent.split())} words]"
                    )
                    return

                # Rejected
                self.total_rejections += 1
                self.cat_rejected[spec.category] += 1
                rejections = reasons
                first_reason = reasons[0] if reasons else "Unknown error"
                self.log_event(f"REJECT {spec.job_id}: {first_reason}")
                with open("rejections.log", "a", encoding="utf-8") as rf:
                    rf.write(f"{spec.job_id} [{spec.category}]: {reasons}\n")

            self.cat_inflight[spec.category] -= 1

    def _render_ui(self, progress: Progress, task_id: Any) -> Layout:
        """Compose Rich UI layout panels."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=4),
            Layout(name="progress", size=3),
            Layout(name="body"),
            Layout(name="footer", size=8),
        )

        header_text = (
            f"[bold cyan]Model:[/bold cyan] {self.model}  |  "
            f"[bold cyan]Concurrency:[/bold cyan] {self.concurrency}  |  "
            f"[bold cyan]Seed:[/bold cyan] {self.seed}  |  "
            f"[bold cyan]Mode:[/bold cyan] "
            f"{'OFFLINE DRY-RUN' if self.dry_run else 'LIVE GEMINI API'}"
        )
        layout["header"].update(
            Panel(
                Text.from_markup(header_text),
                title="[bold yellow]KernelGemma Dataset Engine[/bold yellow]",
                border_style="yellow",
            )
        )

        layout["progress"].update(progress)

        # Body: split into Category Table and Stats Panel
        layout["body"].split_row(
            Layout(name="categories", ratio=3),
            Layout(name="stats", ratio=2),
        )

        # Category Table
        cat_table = Table(title="Category Quotas & Ingest State", expand=True)
        cat_table.add_column("Cat", style="cyan", width=5)
        cat_table.add_column("Target", justify="right", width=7)
        cat_table.add_column("Accepted", justify="right", width=9)
        cat_table.add_column("Rejected", justify="right", width=9)
        cat_table.add_column("In-Flight", justify="right", width=9)
        cat_table.add_column("Status", justify="center", width=12)

        for cat, target in self.quotas.items():
            acc = self.cat_accepted[cat]
            rej = self.cat_rejected[cat]
            inf = self.cat_inflight[cat]

            if acc >= target:
                status = "[bold green]COMPLETE[/bold green]"
            elif rej > acc and rej > 5:
                status = "[bold red]HIGH REJECT[/bold red]"
            else:
                status = "[bold yellow]IN PROGRESS[/bold yellow]"

            cat_table.add_row(
                cat,
                str(target),
                str(acc),
                str(rej),
                str(inf),
                status,
            )

        layout["categories"].update(cat_table)

        # Stats Panel
        elapsed = max(0.1, time.time() - self.start_time)
        rows_per_min = (len(self.accepted_rows) / elapsed) * 60.0
        avg_lat = (
            sum(self.latencies) / len(self.latencies)
            if self.latencies
            else 0.0
        )
        cooldown_str = (
            f"[bold red]{self.cooldown_remaining:.1f}s ACTIVE[/bold red]"
            if self.cooldown_remaining > 0
            else "[green]IDLE[/green]"
        )

        stats_lines = [
            f"[bold]Total API Calls:[/bold] {self.total_api_calls}",
            f"[bold]Retries / Backoffs:[/bold] {self.total_retries}",
            f"[bold]HTTP 429 Hits:[/bold] {self.total_429s}",
            f"[bold]Avg Latency:[/bold] {avg_lat:.1f} ms",
            f"[bold]Generation Rate:[/bold] {rows_per_min:.1f} rows/min",
            f"[bold]Rate-limit Cooldown:[/bold] {cooldown_str}",
            f"[bold]Total Attempts:[/bold] {self.total_attempts} / "
            f"{self.total_rows * 4}",
        ]
        layout["stats"].update(
            Panel(
                Text.from_markup("\n".join(stats_lines)),
                title="Engine Telemetry",
                border_style="cyan",
            )
        )

        # Footer: Rolling Event Log
        event_lines = (
            self.recent_events
            if self.recent_events
            else ["Waiting for jobs..."]
        )
        layout["footer"].update(
            Panel(
                Text.from_markup("\n".join(event_lines)),
                title="Rolling Event Log (Last 5)",
                border_style="dim",
            )
        )

        return layout

    async def run(self) -> int:
        """Execute the generation run and write final atomic dataset."""
        if not self.dry_run and not self.api_key:
            console = _make_console()
            console.print(
                "[bold red]Error:[/bold red] GEMINI_API_KEY environment "
                "variable is not set. Provide it via .env or environment, "
                "or run with --dry-run."
            )
            return 1

        self.load_existing_manifest()

        # Open file handles for incremental append
        mode = "a" if self.resume else "w"
        self._dataset_fp = open(self.output_path, mode, encoding="utf-8")
        self._manifest_fp = open(self.manifest_path, mode, encoding="utf-8")

        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        timeout = aiohttp.ClientTimeout(total=120)

        _ui_console = _make_console()
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=_ui_console,
        )
        task_id = progress.add_task(
            "Generating Dataset",
            total=self.total_rows,
            completed=len(self.accepted_rows),
        )

        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            ) as session:
                worker_session = None if self.dry_run else session
                tasks = [
                    asyncio.create_task(
                        self._process_job(spec, worker_session, semaphore)
                    )
                    for spec in self.specs
                ]

                with Live(
                    self._render_ui(progress, task_id),
                    refresh_per_second=4,
                    console=_ui_console,
                ) as live:
                    while not all(t.done() for t in tasks):
                        progress.update(
                            task_id, completed=len(self.accepted_rows)
                        )
                        live.update(self._render_ui(progress, task_id))
                        if len(self.accepted_rows) >= self.total_rows:
                            for t in tasks:
                                if not t.done():
                                    t.cancel()
                            break
                        await asyncio.sleep(0.25)

                    await asyncio.gather(*tasks, return_exceptions=True)
                    progress.update(task_id, completed=len(self.accepted_rows))
                    live.update(self._render_ui(progress, task_id))

        except (asyncio.CancelledError, KeyboardInterrupt):
            console = _make_console()
            console.print(
                "\n[bold yellow]Graceful shutdown requested.[/bold yellow]"
            )
            console.print(
                "Progress saved. Resume anytime with:\n"
                "  python dataset_engine.py --resume\n"
                f"  --output {self.output_path}"
            )
            return 130
        finally:
            self._dataset_fp.flush()
            self._dataset_fp.close()
            self._manifest_fp.flush()
            self._manifest_fp.close()

        # Check completion status
        if len(self.accepted_rows) < self.total_rows:
            console = _make_console()
            console.print(
                "[bold red]Failed:[/bold red] Reached only "
                f"{len(self.accepted_rows)} accepted rows out of "
                f"{self.total_rows} requested."
            )
            return 2

        # Deterministic shuffle and atomic rewrite
        self._atomic_shuffle_and_rewrite()

        # Verify integrity and print final summary
        self._print_completion_summary()
        verify_dataset_integrity(self.output_path, self.total_rows)

        return 0

    def _atomic_shuffle_and_rewrite(self) -> None:
        """Deterministic shuffle and atomic rewrite of dataset and manifest."""
        rng = random.Random(self.seed)
        shuffled = list(self.accepted_rows)
        rng.shuffle(shuffled)

        tmp_dataset = f"{self.output_path}.tmp"
        tmp_manifest = f"{self.manifest_path}.tmp"

        with (
            open(tmp_dataset, "w", encoding="utf-8") as df,
            open(tmp_manifest, "w", encoding="utf-8") as mf,
        ):
            for row in shuffled:
                row_dict = {
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": row.intent},
                        {"role": "assistant", "content": row.code},
                    ]
                }
                df.write(json.dumps(row_dict, ensure_ascii=False) + "\n")

                manifest_dict = {
                    "job_id": row.job_id,
                    "category": row.category,
                    "intent_hash": row.intent_hash,
                    "code_hash": row.code_hash,
                    "tier": row.tier,
                    "style": row.style,
                    "params": row.params,
                    "timestamp": row.timestamp,
                }
                mf.write(json.dumps(manifest_dict, ensure_ascii=False) + "\n")

        os.replace(tmp_dataset, self.output_path)
        os.replace(tmp_manifest, self.manifest_path)

    def _print_completion_summary(self) -> None:
        """Display final statistics table upon run completion."""
        console = _make_console()
        elapsed = time.time() - self.start_time
        xdp_count = sum(
            1 for r in self.accepted_rows if r.category.startswith("X")
        )
        kprobe_count = sum(
            1 for r in self.accepted_rows if r.category.startswith("K")
        )

        file_size = (
            os.path.getsize(self.output_path)
            if os.path.exists(self.output_path)
            else 0
        )
        hasher = hashlib.sha256()
        with open(self.output_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        dataset_sha256 = hasher.hexdigest()

        summary_table = Table(
            title="KernelGemma Dataset Generation Complete",
            show_header=True,
            header_style="bold magenta",
        )
        summary_table.add_column("Metric", style="cyan", width=26)
        summary_table.add_column("Value", style="bold white")

        summary_table.add_row(
            "Total Accepted Rows", str(len(self.accepted_rows))
        )
        summary_table.add_row(
            "Composition Split",
            f"XDP: {xdp_count} "
            f"({xdp_count * 100 // len(self.accepted_rows)}%) | "
            f"kprobe: {kprobe_count} "
            f"({kprobe_count * 100 // len(self.accepted_rows)}%)",
        )
        summary_table.add_row("Total Rejections", str(self.total_rejections))
        summary_table.add_row("Total Wall Time", f"{elapsed:.2f} seconds")
        summary_table.add_row("Dataset File", self.output_path)
        summary_table.add_row("Sidecar Manifest", self.manifest_path)
        summary_table.add_row("Dataset Size", f"{file_size:,} bytes")
        summary_table.add_row("SHA-256 Checksum", dataset_sha256)

        console.print("\n")
        console.print(summary_table)


# ====================================================================
# INTEGRITY VERIFICATION PASS
# ====================================================================


def verify_dataset_integrity(file_path: str, expected_rows: int) -> None:
    """Perform byte-exact validation pass on generated JSONL dataset."""
    console = _make_console()
    console.print("\n[bold cyan]Verifying dataset integrity...[/bold cyan]")

    with open(file_path, "r", encoding="utf-8") as f:
        raw_content = f.read()

    assert not raw_content.endswith("\n\n"), (
        "Dataset contains trailing blank line!"
    )

    lines = raw_content.splitlines()
    assert len(lines) == expected_rows, (
        f"Line count mismatch: expected {expected_rows}, got {len(lines)}."
    )

    seen_intent_hashes: set[str] = set()
    seen_code_hashes: set[str] = set()

    for idx, line in enumerate(lines):
        assert line.strip(), f"Row {idx} is empty!"
        obj = json.loads(line)
        assert list(obj.keys()) == ["messages"], (
            f"Row {idx} has invalid keys: {list(obj.keys())}"
        )
        msgs = obj["messages"]
        assert len(msgs) == 3, f"Row {idx} messages count != 3."

        # Verify system turn
        assert msgs[0]["role"] == "system"
        assert msgs[0]["content"] == SYSTEM_PROMPT, (
            f"Row {idx} system prompt mismatch."
        )

        # Verify user turn
        assert msgs[1]["role"] == "user"
        intent = msgs[1]["content"]
        words = intent.split()
        assert 8 <= len(words) <= 60, (
            f"Row {idx} intent word count {len(words)} outside 8-60 range."
        )
        for tok in ("#include", "SEC(", "bpf_"):
            assert tok not in intent, f"Row {idx} intent contains token {tok}."

        # Verify assistant turn
        assert msgs[2]["role"] == "assistant"
        code = msgs[2]["content"]
        assert "```" not in code, f"Row {idx} code contains markdown fences."
        assert code.endswith("\n"), (
            f"Row {idx} code does not end with newline."
        )
        assert not code.startswith("\n"), (
            f"Row {idx} code has leading newline."
        )

        # Deduplication check
        i_hash = compute_intent_hash(intent)
        c_hash = compute_code_hash(code)
        assert i_hash not in seen_intent_hashes, (
            f"Row {idx} has duplicate intent hash!"
        )
        assert c_hash not in seen_code_hashes, (
            f"Row {idx} has duplicate code hash!"
        )
        seen_intent_hashes.add(i_hash)
        seen_code_hashes.add(c_hash)

    console.print(
        f"[bold green]✓ Integrity check PASSED: {expected_rows} valid, "
        "unique, strictly compliant rows.[/bold green]\n"
    )


# ====================================================================
# CLI ENTRY POINT
# ====================================================================


def main() -> None:
    """CLI parser and program execution entry point."""
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="KernelGemma verifier-safe eBPF synthetic dataset engine."
    )
    parser.add_argument(
        "--rows",
        type=int,
        default=300,
        help="Number of training rows to generate (default: 300).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="kernelgemma_dataset.jsonl",
        help="Output dataset file path (default: kernelgemma_dataset.jsonl).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
        help="Gemini model ID (default: gemini-2.5-flash).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=8,
        help="Max concurrent async workers (default: 8).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic PRNG seed (default: 42).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume generation from existing sidecar manifest.",
    )
    parser.add_argument(
        "--clang-check",
        action="store_true",
        help="Validate generated C code via clang -target bpf if installed.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Run offline generator using parameterised templates "
            "(zero API calls)."
        ),
    )

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )

    engine = DatasetEngine(
        rows=args.rows,
        output_path=args.output,
        model=args.model,
        concurrency=args.concurrency,
        seed=args.seed,
        resume=args.resume,
        clang_check=args.clang_check,
        dry_run=args.dry_run,
    )

    exit_code = asyncio.run(engine.run())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
