%TST_OBJECT  Loading and running Octave authored eBPF programs.

%!test  % an XDP program loads and runs through BPF_PROG_TEST_RUN
%! if (bpf.have_bpf ())
%!   R = bpf.regs ();
%!   b = bpf.Builder ('GPL');
%!   b.map ('hits', 'array', 'u32', 'u64', 1);
%!   p = b.program ('xdp', 'counter');
%!   p.st_w (R.R10, -4, 0);
%!   p.ld_map_fd (R.R1, 'hits');
%!   p.mov64_reg (R.R2, R.R10);
%!   p.add64_imm (R.R2, -4);
%!   p.call (bpf.helper ('map_lookup_elem'));
%!   p.jeq_imm (R.R0, 0, 'done');
%!   p.mov64_imm (R.R1, 1);
%!   p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
%!   p.label ('done');
%!   p.mov64_imm (R.R0, 2);
%!   p.exit ();
%!
%!   obj = b.build ();
%!   obj.load ();
%!   prog = obj.find_program ('counter');
%!   r = prog.test_run (uint8 (zeros (1, 100)));
%!   assert (r.retval, 2);
%!   assert (obj.find_map ('hits').lookup (0), uint64 (1));
%!   clear obj
%! endif

%!test  % a rejected program reports the verifier log
%! if (bpf.have_bpf ())
%!   b = bpf.Builder ('GPL');
%!   p = b.program ('xdp', 'bad');
%!   p.ldx_dw (0, 1, 0);         % 8 byte load from an XDP context: invalid
%!   p.exit ();
%!   obj = b.build ();
%!   obj.set_log (65536);
%!   failed = false;
%!   try
%!     obj.load ();
%!   catch
%!     failed = true;
%!   end
%!   assert (failed);
%!   clear obj
%! endif

%!test  % object metadata is exposed
%! if (bpf.have_bpf ())
%!   b = bpf.Builder ('GPL');
%!   b.map ('m', 'array', 'u32', 'u64', 2);
%!   p = b.program ('xdp', 'x');
%!   p.mov64_imm (0, 2);
%!   p.exit ();
%!   obj = b.build ();
%!   assert (numel (obj.program_names ()), 1);
%!   assert (strcmp (obj.program_names (){1}, 'x'));
%!   assert (strcmp (obj.map_names (){1}, 'm'));
%!   clear obj
%! endif

%!test  % an invalid in-memory image is rejected
%! fail ('bpf.Object.from_mem (uint8 (1:32), ''junk'')', 'libbpf');

%!test  % builder metadata
%! b = bpf.Builder ('GPL');
%! b.map ('a', 'array', 'u32', 'u64', 1);
%! b.map ('b', 'hash', 'u32', 'u32', 4);
%! assert (b.map_names (), {'a', 'b'});
%! m = b.find_map ('b');
%! assert (strcmp (m.type_name, 'BPF_MAP_TYPE_HASH'));
%! assert (m.max_entries, 4);
