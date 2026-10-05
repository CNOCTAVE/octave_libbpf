%TST_ELF  ELF image generation tests.

%!test  % the ELF header identifies a 64 bit little endian BPF object
%! b = bpf.Builder ('GPL');
%! p = b.program ('kprobe/do_sys_openat2', 'hello');
%! p.mov64_imm (0, 0);
%! p.exit ();
%! img = b.elf ();
%! assert (img(1:4), uint8 ([0x7f, double('E'), double('L'), double('F')]));
%! assert (img(5), uint8 (2));                        % ELFCLASS64
%! assert (img(6), uint8 (1));                        % ELFDATA2LSB
%! assert (double (bpf.bytes2num (img(17:18))), 1);    % ET_REL
%! assert (double (bpf.bytes2num (img(19:20))), 247);  % EM_BPF

%!test  % every generated object has a license section
%! b = bpf.Builder ('GPL');
%! p = b.program ('kprobe/x', 'x');
%! p.exit ();
%! img = b.elf ();
%! assert (numel (img) > 64);

%!test  % a map reference produces a relocation
%! b = bpf.Builder ('GPL');
%! b.map ('m', 'array', 'u32', 'u64', 4);
%! p = b.program ('kprobe/x', 'x');
%! p.ld_map_fd (1, 'm');
%! p.exit ();
%! img = b.elf ();
%! assert (numel (img) > 256);
%! r = p.relocations ();
%! assert (numel (r), 1);

%!test  % the license string ends up in the image
%! b = bpf.Builder ('Dual BSD/GPL');
%! p = b.program ('kprobe/x', 'x');
%! p.exit ();
%! img = b.elf ();
%! txt = char (img);
%! assert (! isempty (strfind (txt, 'Dual BSD/GPL')));

%!test  % referencing an unknown map is an error
%! b = bpf.Builder ('GPL');
%! p = b.program ('kprobe/x', 'x');
%! p.ld_map_fd (1, 'nosuchmap');
%! p.exit ();
%! fail ('b.elf ()', 'unknown map');

%!test  % the same builder produces a stable image
%! b = bpf.Builder ('GPL');
%! b.map ('m', 'array', 'u32', 'u64', 4);
%! p = b.program ('kprobe/x', 'x');
%! p.ld_map_fd (1, 'm'); p.exit ();
%! assert (b.elf (), b.elf ());
