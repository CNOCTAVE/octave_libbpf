%TST_BTF  BTF encoder tests.

%!test  % integer types carry the right size and bit width
%! B = bpf.BtfBuilder ();
%! i1 = B.add_int ('int', 4, bpf.BtfBuilder.ENC_SIGNED);
%! i8 = B.add_int ('unsigned long long', 8, 0);
%! assert (B.size_of (i1), 4);
%! assert (B.size_of (i8), 8);
%! assert (B.kind_of (i1), bpf.BtfBuilder.KIND_INT);
%! assert (B.name_of (i8), 'unsigned long long');

%!test  % pointers and arrays
%! B = bpf.BtfBuilder ();
%! i4 = B.add_int ('int', 4, 1);
%! p = B.add_ptr (i4);
%! a = B.add_array (i4, 4, i4);
%! assert (B.size_of (p), 8);
%! assert (B.size_of (a), 16);

%!test  % structures are laid out with natural alignment
%! B = bpf.BtfBuilder ();
%! u8 = B.add_int ('unsigned char', 1, 0);
%! u64 = B.add_int ('unsigned long long', 8, 0);
%! members = struct ('name', {'a', 'b'}, 'type', {u8, u64});
%! s = B.add_struct ('thing', members);
%! assert (B.size_of (s), 16);

%!test  % the header and the string table are well formed
%! B = bpf.BtfBuilder ();
%! B.add_int ('int', 4, 1);
%! b = B.bytes ();
%! assert (b(1), uint8 (0x9f));
%! assert (b(2), uint8 (0xeb));
%! assert (b(3), uint8 (1));            % version
%! assert (double (bpf.bytes2num (b(5:8))), 24);  % hdr_len
%! assert (double (bpf.bytes2num (b(9:12))), 0);  % type_off
%! type_len = double (bpf.bytes2num (b(13:16)));
%! str_off = double (bpf.bytes2num (b(17:20)));
%! str_len = double (bpf.bytes2num (b(21:24)));
%! assert (str_off, type_len);
%! assert (numel (b), 24 + type_len + str_len);

%!test  % an object BTF round trips through the parser
%! if (bpf.have_bpf ())
%!   b = bpf.Builder ('GPL');
%!   b.map ('counts', 'array', 'u32', 'u64', 8);
%!   f = tempname ();
%!   fid = fopen (f, 'wb'); fwrite (fid, b.elf (), 'uint8'); fclose (fid);
%!   B = bpf.BTF.from_file (f);
%!   unlink (f);
%!   assert (B.type_cnt () > 0);
%!   id = B.find_by_name_kind ('counts', bpf.BTF.KIND_VAR);
%!   assert (id > 0);
%! endif
