"""Test suite for KernelGemma static validator gate."""

from __future__ import annotations

from dataset_engine import validate_sample

EXEMPLAR_A_INTENT = (
    "Drop all inbound traffic from 203.0.113.50 at the earliest point "
    "in the network stack."
)

EXEMPLAR_A_CODE = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_src_ip(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->saddr == bpf_htonl(0xCB007132))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

EXEMPLAR_B_INTENT = (
    "Log every process execution on the host with the PID, command name, "
    "and binary path."
)

EXEMPLAR_B_CODE = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ptrace.h>
#define __TARGET_ARCH_x86
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define COMM_LEN 16
#define PATH_LEN 128

SEC("kprobe/__x64_sys_execve")
int trace_execve(struct pt_regs *ctx)
{
    struct pt_regs *sregs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    const char *filename_ptr = NULL;
    char filename[PATH_LEN] = {};
    char comm[COMM_LEN] = {};
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr),
                          &PT_REGS_PARM1(sregs));
    bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_printk("execve pid=%d comm=%s file=%s", pid, comm, filename);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"""


# ====================================================================
# ACCEPTING CASES (at least 6)
# ====================================================================


def test_accept_exemplar_a() -> None:
    """Validate that Gold Exemplar A passes all validation checks."""
    reasons = validate_sample(EXEMPLAR_A_INTENT, EXEMPLAR_A_CODE)
    assert not reasons, f"Exemplar A rejected: {reasons}"


def test_accept_exemplar_b() -> None:
    """Validate that Gold Exemplar B passes all validation checks."""
    reasons = validate_sample(EXEMPLAR_B_INTENT, EXEMPLAR_B_CODE)
    assert not reasons, f"Exemplar B rejected: {reasons}"


def test_accept_xdp_tcp_port_drop() -> None:
    """Validate XDP TCP port drop with proper L4 bounds check."""
    intent = (
        "Discard inbound TCP network traffic addressed to destination "
        "port 8080 at ingress."
    )
    code = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_tcp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(8080))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""
    reasons = validate_sample(intent, code)
    assert not reasons, f"XDP TCP drop rejected: {reasons}"


def test_accept_xdp_syn_lru_map() -> None:
    """Validate XDP SYN flood mitigation using LRU hash map and NULL check."""
    intent = (
        "Mitigate SYN flood attacks by maintaining source connection "
        "counts in an LRU hash table."
    )
    code = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} syn_map SEC(".maps");

SEC("xdp")
int xdp_syn_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr))
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn || tcp->ack)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 *cnt = bpf_map_lookup_elem(&syn_map, &src_ip);
    if (!cnt) {
        __u64 init_cnt = 1;
        bpf_map_update_elem(&syn_map, &src_ip, &init_cnt, BPF_ANY);
        return XDP_PASS;
    }

    __sync_fetch_and_add(cnt, 1);
    if (*cnt > 1000)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""
    reasons = validate_sample(intent, code)
    assert not reasons, f"XDP SYN map sample rejected: {reasons}"


def test_accept_kprobe_openat_path() -> None:
    """Validate kprobe sys_openat monitoring with bounded unrolled loop."""
    intent = (
        "Monitor filesystem open attempts and generate security alerts "
        "when shadow file is accessed."
    )
    code = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ptrace.h>
#define __TARGET_ARCH_x86
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PATH_LEN 64

SEC("kprobe/__x64_sys_openat")
int trace_openat(struct pt_regs *ctx)
{
    struct pt_regs *sregs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    const char *filename_ptr = NULL;
    char path[PATH_LEN] = {};
    static const char target[] = "/etc/shadow";
    int match = 1;

    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr),
                          &PT_REGS_PARM2(sregs));
    bpf_probe_read_user_str(path, sizeof(path), filename_ptr);

    #pragma unroll
    for (int i = 0; i < 11; i++) {
        if (path[i] != target[i]) {
            match = 0;
            break;
        }
    }

    if (match) {
        __u32 pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("openat sensitive target hit by pid=%d", pid);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"""
    reasons = validate_sample(intent, code)
    assert not reasons, f"kprobe openat sample rejected: {reasons}"


def test_accept_xdp_fragment_drop() -> None:
    """Validate XDP drop of fragmented IPv4 packets."""
    intent = (
        "Enforce network perimeter policy to drop fragmented IPv4 datagrams "
        "at network ingress."
    )
    code = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_frags(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (bpf_ntohs(ip->frag_off) & 0x3FFF)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""
    reasons = validate_sample(intent, code)
    assert not reasons, f"XDP frag drop sample rejected: {reasons}"


# ====================================================================
# REJECTING CASES (at least 8)
# ====================================================================


def test_reject_missing_mandatory_include() -> None:
    """Reject code missing one of the mandatory includes."""
    # Remove #include <linux/ip.h>
    bad_code = EXEMPLAR_A_CODE.replace("#include <linux/ip.h>\n", "")
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("First 4 includes" in r for r in reasons)


def test_reject_disallowed_include() -> None:
    """Reject code containing non-whitelisted header."""
    bad_code = "#include <stdio.h>\n" + EXEMPLAR_A_CODE
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("Disallowed include header: <stdio.h>" in r for r in reasons)


def test_reject_missing_bounds_check() -> None:
    """Reject XDP code without the mandatory prologue bounds check."""
    bad_code = EXEMPLAR_A_CODE.replace(
        "if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)\n"
        "        return XDP_PASS;\n\n",
        "",
    )
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("Missing mandatory XDP bounds-check" in r for r in reasons)


def test_reject_bounds_check_after_dereference() -> None:
    """Reject XDP code accessing eth-> before bounds check."""
    bad_code = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_early_deref(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("must appear BEFORE first eth->" in r for r in reasons)


def test_reject_forbidden_tc_hook() -> None:
    """Reject program using forbidden tc/classifier hook."""
    bad_code = EXEMPLAR_A_CODE.replace('SEC("xdp")', 'SEC("tc")')
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("Disallowed SEC" in r or "Forbidden hook" in r for r in reasons)


def test_reject_forbidden_xdp_action() -> None:
    """Reject XDP program returning XDP_TX."""
    bad_code = EXEMPLAR_A_CODE.replace("return XDP_DROP;", "return XDP_TX;")
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("Forbidden XDP action 'XDP_TX'" in r for r in reasons)


def test_reject_unknown_helper() -> None:
    """Reject code invoking a non-whitelisted BPF helper."""
    bad_code = EXEMPLAR_B_CODE.replace("bpf_printk(", "bpf_trace_printk(")
    reasons = validate_sample(EXEMPLAR_B_INTENT, bad_code)
    assert any("bpf_trace_printk" in r for r in reasons)


def test_reject_markdown_fences() -> None:
    """Reject code containing markdown code fences."""
    bad_code = f"```c\n{EXEMPLAR_A_CODE}\n```"
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("markdown fences" in r for r in reasons)


def test_reject_unbounded_while_loop() -> None:
    """Reject code containing forbidden while loop."""
    bad_code = EXEMPLAR_A_CODE.replace(
        "return XDP_PASS;", "while (1) { } return XDP_PASS;"
    )
    reasons = validate_sample(EXEMPLAR_A_INTENT, bad_code)
    assert any("Forbidden 'while' loop" in r for r in reasons)


def test_reject_unchecked_map_lookup() -> None:
    """Reject map lookup result used without a NULL check."""
    code_unchecked = """#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

SEC("xdp")
int xdp_unchecked(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    __u32 key = 1;
    __u64 *val = bpf_map_lookup_elem(&counters, &key);
    __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""
    reasons = validate_sample(EXEMPLAR_A_INTENT, code_unchecked)
    assert any("without subsequent NULL check" in r for r in reasons)


def test_reject_intent_word_count() -> None:
    """Reject intent with fewer than 8 words or more than 60 words."""
    short_intent = "Drop host traffic."
    reasons = validate_sample(short_intent, EXEMPLAR_A_CODE)
    assert any("outside 8-60 range" in r for r in reasons)

    long_intent = " ".join(["word"] * 65)
    reasons2 = validate_sample(long_intent, EXEMPLAR_A_CODE)
    assert any("outside 8-60 range" in r for r in reasons2)


def test_reject_intent_forbidden_tokens() -> None:
    """Reject intent containing technical tokens like #include, SEC(, bpf_."""
    bad_intent = (
        "Please generate an eBPF program with SEC(xdp) to drop bad packets."
    )
    reasons = validate_sample(bad_intent, EXEMPLAR_A_CODE)
    assert any("forbidden technical token" in r for r in reasons)


def test_reject_duplicate_detection() -> None:
    """Reject exact normalized intent and Jaccard similarity above 0.85."""
    existing_intents = [
        "Drop all inbound traffic from 203.0.113.50 at the network ingress."
    ]
    # High similarity (> 0.85)
    similar_intent = (
        "Drop all inbound traffic from 203.0.113.50 at the network ingress."
    )
    reasons = validate_sample(
        similar_intent,
        EXEMPLAR_A_CODE,
        existing_intents=existing_intents,
    )
    assert any("Duplicate" in r or "Jaccard similarity" in r for r in reasons)
