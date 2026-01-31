// eBPF Process Network Watcher
// Tracks which applications make outbound network connections
// Simple and focused: just tcp_connect monitoring

//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

// Simple event: which process connected where
// Packed to ensure exact memory layout matches Go struct
struct connection_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 dst_ip;         // Where they connected to
    __u16 dst_port;       // What port
    __u16 _pad;           // Padding for alignment
    char comm[TASK_COMM_LEN]; // Process name
} __attribute__((packed));

// Make sure BTF is generated for our struct
struct connection_event *unused_event __attribute__((unused));

// Ring buffer to send events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Track outbound TCP connections
// This fires when any app tries to connect to the internet
SEC("kprobe/tcp_connect")
int trace_connect(struct pt_regs *ctx) {
    struct connection_event event = {};
    struct sock *sk;
    
    // Get the first argument (struct sock *sk)
    // On ARM64, first arg is in regs[0]
    bpf_probe_read(&sk, sizeof(sk), &ctx->regs[0]);
    
    // Get process info
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.timestamp_ns = bpf_ktime_get_ns();
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get destination IP and port
    event.dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event.dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    
    // Send to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}
