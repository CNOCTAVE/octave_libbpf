function demo_octave_libbpf ()
%DEMO_OCTAVE_LIBBPF  Short tour of the octave_libbpf package.
%
%   demo_octave_libbpf runs a handful of self contained demonstrations:
%   instruction encoding, BTF and ELF generation, and - when the process is
%   allowed to use eBPF - a program that is loaded and executed by the
%   kernel.  See the examples/ directory for longer, more realistic
%   programs.

  printf ('\n=== 1. eBPF instruction encoding ===\n');
  b = bpf.Insn ('st_w', 10, -4, 0);
  printf ('st_w r10, -4, 0  ->  %s\n', mat2str (double (b)));
  printf ('bpf.helper (''map_lookup_elem'') = %d\n', bpf.helper ('map_lookup_elem'));

  printf ('\n=== 2. assembler with labels ===\n');
  R = bpf.regs ();
  a = bpf.Asm ();
  a.mov64_imm (R.R0, 1);
  a.jeq_imm (R.R0, 1, 'skip');
  a.mov64_imm (R.R0, 2);
  a.label ('skip');
  a.exit ();
  disp (a.source ());
  printf ('%d instructions, %d bytes\n', a.count (), numel (a.bytes ()));

  printf ('\n=== 3. ELF64/BPF object with a BTF described map ===\n');
  b = bpf.Builder ('GPL');
  b.map ('counts', 'array', 'u32', 'u64', 8);
  p = b.program ('xdp', 'demo');
  p.mov64_imm (R.R0, 2);
  p.exit ();
  img = b.elf ();
  printf ('generated a %d byte ELF image\n', numel (img));
  printf ('header magic: %s, machine: %d (EM_BPF)\n', ...
          char (img(1:4)), bpf.bytes2num (img(19:20)));

  printf ('\n=== 4. running it in the kernel ===\n');
  if (~ bpf.have_bpf ())
    printf ('skipped: this process may not load eBPF programs\n');
    printf ('(needs CAP_BPF or CAP_SYS_ADMIN)\n');
    return;
  end
  obj = b.build ();
  obj.load ();
  r = obj.find_program ('demo').test_run (uint8 (zeros (1, 64)));
  printf ('BPF_PROG_TEST_RUN returned %d (XDP_PASS)\n', r.retval);
  clear obj

  printf ('\n=== 5. maps from Octave ===\n');
  m = bpf.Map.create ('hash', 4, 8, 8, 'demo_hash');
  m.update (1, 111);
  m.update (2, 222);
  printf ('m[1] = %d, m[2] = %d\n', m.lookup (1), m.lookup (2));
  m.remove (1);
  printf ('after remove(1): %s\n', mat2str (cell2mat (m.keys ())));
  clear m
  printf ('\ndone\n');
end
