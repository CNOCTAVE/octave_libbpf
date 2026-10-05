%HELLO_KPROBE  Count calls to do_sys_openat2() from an eBPF program written in Octave.
%
%   Run with:  pkg load octave_libbpf;  hello_kprobe
%
%   The eBPF program below is assembled to BPF byte code, packed into an
%   ELF64/BPF object together with a BTF description of the 'counts' array
%   map, loaded by libbpf and attached as a kprobe.  No C compiler and no
%   clang are involved.

pkg load octave_libbpf

R = bpf.regs ();

b = bpf.Builder ('GPL');
counts = b.map ('counts', 'array', 'u32', 'u64', 8);

p = b.program ('kprobe/do_sys_openat2', 'count_open');
p.st_w (R.R10, -4, 0);                              % u32 key = 0 on the stack
p.ld_map_fd (R.R1, 'counts');                       % r1 = &counts (relocated)
p.mov64_reg (R.R2, R.R10);                          % r2 = &key
p.add64_imm (R.R2, -4);
p.call (bpf.helper ('map_lookup_elem'));
p.jeq_imm (R.R0, 0, 'done');                        % if (!value) goto done
p.mov64_imm (R.R1, 1);
p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));  % __sync_fetch_and_add (value, 1)
p.label ('done');
p.mov64_imm (R.R0, 0);
p.exit ();

fprintf ('--- generated eBPF program ---\n');
disp (p.source ())

obj = b.build ();
obj.load ();
links = obj.attach_all ();       %#ok<NASGU>  keeps the kprobe attached

map = obj.find_map ('counts');
printf ('counts[0] before = %d\n', map.lookup (0));

fid = fopen ('/etc/hostname', 'r');
if (fid > 0)
  fclose (fid);
end

printf ('counts[0] after  = %d\n', map.lookup (0));

% the object (and therefore the kprobe) is detached when obj goes away
clear obj
printf ('detached\n');
