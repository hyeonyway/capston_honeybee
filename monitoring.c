//go:build ignore

#define __TARGET_ARCH_x86

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Perf 이벤트 데이터 구조체 추가
struct event {
    u64 timestamp;
    u32 pid;
    char comm[16];
    u64 addr;
};

const struct event *unused __attribute__((unused));

// Perf Buffer 맵 추가
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// 이벤트 전송 함수
static __always_inline void send_event(struct pt_regs *ctx, void *addr) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return;

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->addr = (u64)(long)addr;

    bpf_ringbuf_submit(e, 0);
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, void *);
    __type(value, u64);
} freed_skb_addrs SEC(".maps");

/*
SEC("kprobe/kfree_skb")
int BPF_KPROBE(track_kfree_skb, struct sk_buff *skb)
{
    u64 ts = bpf_ktime_get_ns();
    void *addr = (void *)skb;

    if (addr) {
        bpf_map_update_elem(&freed_skb_addrs, &addr, &ts, BPF_ANY);
    }
    return 0;
}
*/

SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    u64 ts = bpf_ktime_get_ns();
    void *addr = (void *)skb;

    if (addr) {
        bpf_map_update_elem(&freed_skb_addrs, &addr, &ts, BPF_ANY);
    }
    return 0;
}


/*
SEC("kprobe/__netif_receive_skb_core")
int BPF_KPROBE(detect_skb_reuse, struct sk_buff *skb)
{
    void *addr = (void *)skb;
    u64 *ts = bpf_map_lookup_elem(&freed_skb_addrs, &addr);

    if (ts) {
        u64 current_time = bpf_ktime_get_ns();
        if (current_time - *ts > 5000000000) { // 5초 이상 지난 경우 제거
            bpf_map_delete_elem(&freed_skb_addrs, &addr);
        } else {
            bpf_printk("Potential UAF detected! SKB reused without reallocation: %p\n", addr);
        }
    }
    return 0;
}
*/

SEC("kprobe/netif_receive_skb")
int BPF_KPROBE(detect_skb_uaf, struct sk_buff *skb) {
    void *addr = (void *)skb;
    u64 *ts = bpf_map_lookup_elem(&freed_skb_addrs, &addr);

    if (ts) {
        u64 now = bpf_ktime_get_ns();
        if (now - *ts <= 5000000000) {
            send_event(ctx, addr);
            bpf_printk("[UAF] skb reused after free: %p\n", addr);
        }
    }
    return 0;
}

// skb 재할당 시 제거 (정상 재할당은 UAF 아님)
SEC("kretprobe/__alloc_skb")
int BPF_KRETPROBE(clean_alloc_skb, struct sk_buff *skb) {
    void *addr = (void *)skb;
    if (addr)
        bpf_map_delete_elem(&freed_skb_addrs, &addr);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";