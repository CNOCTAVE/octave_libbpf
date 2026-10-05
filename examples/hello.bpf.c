// A minimal clang compiled eBPF program, loadable through bpf.Object.
//
//   clang -target bpf -g -O2 -c examples/hello.bpf.c -o examples/hello.bpf.o
//
// (the include paths must point at the libbpf headers shipped with the
// package or installed by libbpf-devel).

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");

SEC("kprobe/do_sys_openat2")
int hello(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u64 *v = bpf_map_lookup_elem(&counts, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
