%TST_INSN  Instruction encoding tests.

%!test  % mov64_imm r1, 1
%! b = bpf.Insn ('mov64_imm', 1, 1);
%! assert (class (b), 'uint8');
%! assert (size (b), [1, 8]);
%! assert (b, uint8 ([0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]));

%!test  % mov64_reg r2, r10
%! b = bpf.Insn ('mov64_reg', 2, 10);
%! assert (b, uint8 ([0xbf, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

%!test  % mov32_imm is the 32 bit ALU class
%! b = bpf.Insn ('mov32_imm', 0, 7);
%! assert (b(1), uint8 (0xb4));

%!test  % negative offsets and immediates are two's complement
%! b = bpf.Insn ('st_w', 10, -4, 0);
%! assert (b, uint8 ([0x62, 0x0a, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00]));

%!test  % an unconditional branch with a negative offset
%! b = bpf.Insn ('ja', -3);
%! assert (b, uint8 ([0x05, 0x00, 0xfd, 0xff, 0x00, 0x00, 0x00, 0x00]));

%!test  % exit
%! assert (bpf.Insn ('exit'), uint8 ([0x95, 0, 0, 0, 0, 0, 0, 0]));

%!test  % ld_imm64 occupies two instruction slots
%! b = bpf.Insn ('ld_imm64', 1, 5);
%! assert (size (b), [1, 16]);
%! assert (b(1:8), uint8 ([0x18, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]));
%! assert (b(9:16), uint8 ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

%!test  % ld_map_fd uses the BPF_PSEUDO_MAP_FD source register
%! b = bpf.Insn ('ld_map_fd', 1);
%! assert (b(1:8), uint8 ([0x18, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

%!test  % a 64 bit immediate wider than 32 bits
%! b = bpf.Insn ('ld_imm64', 2, 0x123456789);
%! assert (b(5:8), uint8 ([0x89, 0x67, 0x45, 0x23]));
%! assert (b(13:16), uint8 ([0x01, 0x00, 0x00, 0x00]));

%!test  % a call to a helper
%! b = bpf.Insn ('call', bpf.helper ('map_lookup_elem'));
%! assert (b(1), uint8 (0x85));
%! assert (double (bpf.bytes2num (b(5:8))), bpf.helper ('map_lookup_elem'));

%!test  % 64 bit and 32 bit conditional branches use different classes
%! a = bpf.Insn ('jeq_reg', 1, 2, 5);
%! c = bpf.Insn ('jmp32_jeq_reg', 1, 2, 5);
%! assert (a(1), uint8 (0x1d));
%! assert (c(1), uint8 (0x1e));

%!test  % unknown mnemonics are rejected
%! fail ('bpf.Insn (''not_a_real_instruction'', 1, 2)', 'unknown mnemonic');

%!test  % helper and type tables
%! assert (bpf.helper ('map_lookup_elem'), 1);
%! assert (bpf.helper ('bpf_map_lookup_elem'), 1);
%! assert (bpf.map_type ('array'), 2);
%! assert (bpf.map_type ('BPF_MAP_TYPE_RINGBUF'), 27);
%! assert (bpf.prog_type ('kprobe'), 2);
%! assert (bpf.atomic_op ('add'), 1);
%! assert (bpf.atomic_op ('add', false), 0);
%! assert (bpf.atomic_op ('cmpxchg'), 240);

%!test  % asm labels are resolved
%! R = bpf.regs ();
%! a = bpf.Asm ();
%! a.mov64_imm (R.R0, 1);
%! a.jeq_imm (R.R0, 1, 'target');
%! a.mov64_imm (R.R0, 2);
%! a.label ('target');
%! a.exit ();
%! b = a.bytes ();
%! assert (size (b), [4, 8]);
%! assert (b(2, 3:4), uint8 ([1, 0]));       % skip one instruction
%! assert (a.count (), 4);

%!test  % undefined labels are reported
%! a = bpf.Asm ();
%! a.jeq_imm (0, 0, 'nowhere');
%! fail ('a.bytes ()', 'undefined label');

%!test  % map relocations are recorded
%! a = bpf.Asm ();
%! a.ld_map_fd (1, 'mymap');
%! a.exit ();
%! r = a.relocations ();
%! assert (numel (r), 1);
%! assert (r(1).slot, 0);
%! assert (r(1).sym, 'mymap');
%! assert (strcmp (r(1).kind, 'map_fd'));
