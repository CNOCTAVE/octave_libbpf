%NETWORK_XDP_CLASSIFY  An XDP classifier with direct packet access.
%
%   Run with:  pkg load octave_libbpf;  network_xdp_classify
%
%   The program parses the Ethernet header straight out of the XDP context,
%   counts the frame per EtherType in an array map and passes it up the stack.
%   Frames shorter than an Ethernet header are dropped.
%
%   Because XDP programs can be exercised with BPF_PROG_TEST_RUN, the whole
%   thing is verified here without touching a network interface: the example
%   feeds hand-built IPv4, IPv6, ARP and truncated frames to the kernel and
%   prints what the program decided.

pkg load octave_libbpf

if (~ bpf.have_bpf ())
  printf ('skipped: this process may not load eBPF programs\n');
  return;
end

ETH_P_IP   = 0x0800;
ETH_P_IPV6 = 0x86dd;
XDP_ABORTED = 0;
XDP_DROP    = 1;
XDP_PASS    = 2;

R = bpf.regs ();

b = bpf.Builder ('GPL');
proto = b.map ('ethertypes', 'array', 'u32', 'u64', 4);

p = b.program ('xdp', 'classify');
p.ldx_w (R.R2, R.R1, 0);                 % r2 = ctx->data
p.ldx_w (R.R3, R.R1, 4);                 % r3 = ctx->data_end
p.mov64_reg (R.R4, R.R2);
p.add64_imm (R.R4, 14);                  % sizeof (struct ethhdr)
p.jgt_reg (R.R4, R.R3, 'tooshort');      % packet does not contain a header
p.ldx_h (R.R5, R.R2, 12);                % r5 = h_proto
p.mov64_imm (R.R6, 3);                   % bucket 3 = other
p.jeq_imm (R.R5, ETH_P_IP, 'ipv4');
p.jeq_imm (R.R5, ETH_P_IPV6, 'ipv6');
p.ja ('store');
p.label ('ipv4');
p.mov64_imm (R.R6, 1);
p.ja ('store');
p.label ('ipv6');
p.mov64_imm (R.R6, 2);
p.label ('store');
p.stx_w (R.R10, R.R6, -4);               % u32 key = bucket
p.ld_map_fd (R.R1, 'ethertypes');
p.mov64_reg (R.R2, R.R10);
p.add64_imm (R.R2, -4);
p.call (bpf.helper ('map_lookup_elem'));
p.jeq_imm (R.R0, 0, 'pass');
p.mov64_imm (R.R1, 1);
p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
p.label ('pass');
p.mov64_imm (R.R0, XDP_PASS);
p.exit ();
p.label ('tooshort');
p.mov64_imm (R.R0, XDP_DROP);
p.exit ();

obj = b.build ();
obj.load ();
prog = obj.find_program ('classify');

%% ---- hand built frames -----------------------------------------------------
function f = eth_frame (ethertype, payload)
  f = [uint8([0 1 2 3 4 5]), uint8([6 7 8 9 10 11]), ...
       bpf.num2bytes (ethertype, 2), uint8 (payload)];
end

frames = { 'IPv4',  eth_frame (0x0800, zeros (1, 46)),  XDP_PASS;
           'IPv6',  eth_frame (0x86dd, zeros (1, 46)),  XDP_PASS;
           'ARP',   eth_frame (0x0806, zeros (1, 46)),  XDP_PASS;
           'trunc', uint8 (1:8),                        XDP_DROP };

for k = 1:size (frames, 1)
  r = prog.test_run (frames{k, 2});
  verdict = {'ABORTED', 'DROP', 'PASS', 'TX', 'REDIRECT'};
  ok = 'ok';
  if (r.retval ~= frames{k, 3})
    ok = 'MISMATCH';
  end
  printf ('%-6s %4d bytes -> XDP_%s  %s\n', frames{k, 1}, numel (frames{k, 2}), ...
          verdict{r.retval + 1}, ok);
end

m = obj.find_map ('ethertypes');
names = {'IPv4', 'IPv6', 'other', 'unused'};
printf ('\n分类计数:\n');
for k = 0:2
  printf ('  %-6s %d\n', names{k+1}, m.lookup (k));
end

clear obj
