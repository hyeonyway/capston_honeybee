
// SPDX-License-Identifier: GPL-2.0
//go:build ignore
#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define NF_DROP        0
#define NF_ACCEPT      1
#define NF_STOLEN      2
#define NF_QUEUE       3
#define NF_REPEAT      4
#define NF_STOP        5
#define NF_MAX_VERDICT NF_STOP

#define NF_VERDICT_MASK 0x0000ffff


char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

struct event {
    u64 skb_addr;
    int verdict;
};

const struct event *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);          // thread id
    __type(value, void *);     // skb pointer
    __uint(max_entries, 65536);
} skb_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);          // skb address
    __type(value, u64);        // timestamp
    __uint(max_entries, 65536);
} freed_map SEC(".maps");


SEC("kprobe/nf_hook_slow")
int BPF_KPROBE(save_skb, struct sk_buff *skb) {
    u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&skb_map, &tid, &skb, BPF_ANY);

    return 0;
}

SEC("kprobe/kfree_skb")
int BPF_KPROBE(mark_freed_skb, struct sk_buff *skb) {
    u32 tid = bpf_get_current_pid_tgid();
    void **saved = bpf_map_lookup_elem(&skb_map, &tid);
    if (saved && *saved == skb) {
        u64 skb_addr = (u64)skb;
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&freed_map, &skb_addr, &ts, BPF_ANY);
    }
    return 0;
}

SEC("kretprobe/nf_hook_slow")
int BPF_KRETPROBE(check_verdict, int verdict) {
    u32 tid = bpf_get_current_pid_tgid();
    void **skb_ptr = bpf_map_lookup_elem(&skb_map, &tid);
    if (skb_ptr) {
        u64 skb_addr = (u64)(*skb_ptr);
        if (bpf_map_lookup_elem(&freed_map, &skb_addr)) {
            if ((verdict & NF_VERDICT_MASK) != NF_DROP) {
                bpf_send_signal(9);
                struct event *e;
                e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                if (e) {
                    e->skb_addr = skb_addr;
                    e->verdict = verdict;
                    bpf_ringbuf_submit(e, 0);
                }
            }
        }
        bpf_map_delete_elem(&skb_map, &tid);
    }
    return 0;
}

// SEC("kretprobe/nf_hook_slow")
// int BPF_KRETPROBE(check_verdict, int verdict) {
//     u32 tid = bpf_get_current_pid_tgid();
//     void **skb_ptr = bpf_map_lookup_elem(&skb_map, &tid);
//     if (skb_ptr) {
//         u64 skb_addr = (u64)(*skb_ptr);
//         if (bpf_map_lookup_elem(&freed_map, &skb_addr)) {
//             if ((verdict & NF_VERDICT_MASK) != NF_DROP) {
//                 bpf_printk("[UAF DETECTED] skb=0x%llx freed but verdict=%d\n", skb_addr, verdict);
//                 bpf_send_signal(9);
//             }
//         }
//         bpf_map_delete_elem(&skb_map, &tid);
//     }
//     return 0;
//}
