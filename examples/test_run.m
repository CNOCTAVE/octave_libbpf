%TEST_RUN  Write eBPF programs in Octave and run them in the kernel.
%
%   Run with:  pkg load octave_libbpf;  test_run
%
%   BPF_PROG_TEST_RUN executes a program on a packet supplied from userspace
%   without attaching it to any interface, which makes this the easiest way
%   to check that an Octave authored program is correct: every byte is
%   assembled here, the kernel verifies it and the return value comes back
%   straight into Octave.

pkg load octave_libbpf

R = bpf.regs ();

%% A socket filter that keeps the whole packet.
b = bpf.Builder ('GPL');
p = b.program ('socket', 'keep_all');
p.ldx_w (R.R0, R.R1, 0);          % r0 = skb->len
p.exit ();

obj = b.build ();
obj.set_log (65536);              % keep the verifier log around
obj.load ();
prog = obj.find_program ('keep_all');

for len = [64, 512, 1500]
  r = prog.test_run (uint8 (zeros (1, len)));
  printf ('socket filter: %5d byte packet -> retval %d (%d ns)\n', ...
          len, r.retval, r.duration_ns);
end
clear obj

%% An XDP program, the usual way to test packet processing logic.
b = bpf.Builder ('GPL');
pass = b.map ('passes', 'array', 'u32', 'u64', 1);
p = b.program ('xdp', 'count_and_pass');
p.st_w (R.R10, -4, 0);
p.ld_map_fd (R.R1, 'passes');
p.mov64_reg (R.R2, R.R10);
p.add64_imm (R.R2, -4);
p.call (bpf.helper ('map_lookup_elem'));
p.jeq_imm (R.R0, 0, 'done');
p.mov64_imm (R.R1, 1);
p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
p.label ('done');
p.mov64_imm (R.R0, 2);            % XDP_PASS
p.exit ();

obj = b.build ();
obj.load ();
prog = obj.find_program ('count_and_pass');

for k = 1:5
  r = prog.test_run (uint8 (zeros (1, 100)));
  printf ('xdp run %d: retval %d (XDP_PASS)\n', k, r.retval);
end

printf ('packets seen by the program: %d\n', ...
        obj.find_map ('passes').lookup (0));

clear obj
