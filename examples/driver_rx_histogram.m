%DRIVER_RX_HISTOGRAM  Watching the NIC receive path with eBPF and vmlinux BTF.
%
%   Run with:  pkg load octave_libbpf;  driver_rx_histogram
%
%   Driver developers normally cannot instrument a NIC driver without
%   rebuilding the kernel.  The eBPF program below is a kprobe on
%   netif_receive_skb(), the entry point a driver calls for every received
%   frame, and it builds a histogram of skb->len.
%
%   The offset of sk_buff.len is not hard coded: it is read out of the running
%   kernel's BTF (/sys/kernel/btf/vmlinux) from Octave at build time and then
%   emitted as an immediate in the instruction stream.  The program itself
%   contains no version dependent constant, and the skb is dereferenced with
%   bpf_probe_read_kernel() so the verifier accepts it.

pkg load octave_libbpf

if (~ bpf.have_bpf ())
  printf ('skipped: this process may not load eBPF programs\n');
  return;
end

%% ---- resolve sk_buff.len from the running kernel's BTF -------------------
B = bpf.BTF.vmlinux ();
sid = B.find_by_name_kind ('sk_buff', bpf.BTF.KIND_STRUCT);
m = B.members (sid);
len_off = [];
for k = 1:numel (m)
  if (strcmp (m(k).name, 'len'))
    assert (m(k).bitfield == 0, 'sk_buff.len is unexpectedly a bitfield');
    len_off = m(k).bytes;
  end
end
if (isempty (len_off))
  error ('sk_buff.len not found in vmlinux BTF');
end
printf ('kernel BTF: sk_buff is %d bytes, sk_buff.len at byte offset %d\n', ...
        B.type_info (sid).size, len_off);
clear B

R = bpf.regs ();

%% ---- kprobe(netif_receive_skb): histogram of skb->len --------------------
b = bpf.Builder ('GPL');
rx = b.map ('rx_sizes', 'array', 'u32', 'u64', 8);

p = b.program ('kprobe/netif_receive_skb', 'rx_hist');
p.ldx_dw (R.R3, R.R1, 112);                       % arg1 = struct sk_buff *skb
p.mov64_reg (R.R1, R.R10);
p.add64_imm (R.R1, -8);                           % dst = fp - 8
p.mov64_imm (R.R2, 4);                            % sizeof (u32)
p.emit (bpf.Insn ('call', bpf.helper ('probe_read_kernel')));
p.ldx_w (R.R2, R.R10, -8);                        % r2 = skb->len
p.rsh64_imm (R.R2, 8);                            % 256 byte buckets
p.jle_imm (R.R2, 7, 'clamped');
p.mov64_imm (R.R2, 7);
p.label ('clamped');
p.stx_w (R.R10, R.R2, -4);
p.ld_map_fd (R.R1, 'rx_sizes');
p.mov64_reg (R.R2, R.R10);
p.add64_imm (R.R2, -4);
p.call (bpf.helper ('map_lookup_elem'));
p.jeq_imm (R.R0, 0, 'done');
p.mov64_imm (R.R1, 1);
p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
p.label ('done');
p.mov64_imm (R.R0, 0);
p.exit ();

obj = b.build ();
obj.load ();
links = obj.attach_all ();          %#ok<NASGU>
hist = obj.find_map ('rx_sizes');

%% ---- generate loopback traffic --------------------------------------------
payload = uint8 (ones (1, 1200));
for k = 1:40
  s = tcpclient ('127.0.0.1', 9, 'Timeout', 0.2);   % no listener: connect attempt
  clear s
end

pause (0.3);

v = zeros (1, 8);
for k = 0:7
  v(k+1) = hist.lookup (k);
end
printf ('\nnetif_receive_skb() 观察到的帧长直方图（256 字节一档）:\n');
labels = {'0-255', '256-511', '512-767', '768-1023', ...
          '1024-1279', '1280-1535', '1536-1791', '>=1792'};
for k = 1:8
  printf ('  %-10s %5d\n', labels{k}, v(k));
end
printf ('  合计 %d 帧\n', sum (v));

clear obj
