function octave_libbpf ()
%OCTAVE_LIBBPF  Write and run eBPF programs from GNU Octave.
%
%   octave_libbpf is a wrapper around libbpf, the reference userspace
%   library for eBPF, together with a small eBPF toolchain written in
%   Octave itself.  Together they let you author, load, attach, inspect and
%   drive eBPF programs without leaving the Octave prompt - and, for the
%   programs themselves, without a C compiler.
%
%   Getting started
%   ---------------
%       pkg load octave_libbpf
%       demo_octave_libbpf          % or look at the examples/ directory
%
%   Writing an eBPF program in Octave
%   ---------------------------------
%   A bpf.Builder collects maps and programs.  Programs are written with the
%   bpf.Asm assembler; every mnemonic of the eBPF instruction set is
%   available and branches may refer to labels:
%
%       R = bpf.regs ();
%       b = bpf.Builder ('GPL');
%       counts = b.map ('counts', 'array', 'u32', 'u64', 8);
%
%       p = b.program ('kprobe/do_sys_openat2', 'count_open');
%       p.st_w (R.R10, -4, 0);                     % u32 key = 0
%       p.ld_map_fd (R.R1, 'counts');              % r1 = &counts
%       p.mov64_reg (R.R2, R.R10);                 % r2 = &key
%       p.add64_imm (R.R2, -4);
%       p.call (bpf.helper ('map_lookup_elem'));
%       p.jeq_imm (R.R0, 0, 'done');
%       p.mov64_imm (R.R1, 1);
%       p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
%       p.label ('done');
%       p.mov64_imm (R.R0, 0);
%       p.exit ();
%
%       obj = b.build ();        % ELF64/BPF image + BTF, in memory
%       obj.load ();
%       obj.attach_all ();
%       obj.find_map ('counts').lookup (0)
%
%   b.build() assembles the instructions, encodes the BTF that describes
%   each map, lays out an ELF64 relocatable object for EM_BPF (including
%   the symbol table and the map relocations) and hands the bytes to
%   bpf_object__open_mem().  libbpf then does everything it normally does
%   for a clang produced .bpf.o: verification, CO-RE free relocation, map
%   creation, program loading and pinning.
%
%   Loading objects built elsewhere
%   -------------------------------
%       obj = bpf.Object.from_file ('hello.bpf.o');
%       obj = bpf.load_object ('hello.bpf.o', 'attach', true);
%
%   Any eBPF ELF object works, whether it was produced by clang, by the
%   builder above, or by llvm-objcopy from an existing image.
%
%   Maps, ring buffers and perf buffers
%   -----------------------------------
%       m = obj.find_map ('counts');
%       m.update (0, 1234);   m.lookup (0)      % 4/8 byte values as integers
%       m.lookup (0, 'raw')                     % or as uint8 bytes
%
%       rb = bpf.RingBuf (obj.find_map ('events'));
%       [samples, lost] = rb.poll (1000);       % cell array of uint8 samples
%
%       pb = bpf.PerfBuf (obj.find_map ('perf_events'), 8);
%       [samples, lost] = pb.poll (1000);       % structs with cpu and data
%
%   Introspection
%   -------------
%       obj.program_names (), obj.map_names ()
%       obj.find_program ('x').insns ()          % the instruction stream
%       obj.btf ().dump ()                       % BTF as C declarations
%       bpf.version (), bpf.commands ()
%       bpf.probe ('helper', 'xdp', 'map_lookup_elem')
%
%   Permissions
%   -----------
%   Loading eBPF programs requires CAP_BPF (or CAP_SYS_ADMIN on older
%   kernels).  bpf.have_bpf() reports whether the current process can do
%   it, and bpf.memlock() raises RLIMIT_MEMLOCK for kernels older than
%   5.11.  The pure userspace parts of the package (assembler, BTF and ELF
%   generation, type tables) work without any privileges.
%
%   See also bpf.Builder, bpf.Asm, bpf.Object, bpf.Map, bpf.Program,
%   bpf.RingBuf, bpf.PerfBuf, bpf.BTF.

  help ('octave_libbpf');
end
