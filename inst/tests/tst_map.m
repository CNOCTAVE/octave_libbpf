%TST_MAP  Map creation and element access (requires BPF privileges).

%!test  % array maps round trip values
%! if (bpf.have_bpf ())
%!   m = bpf.Map.create ('array', 4, 8, 4, 'octave_tst_array');
%!   assert (m.key_size (), 4);
%!   assert (m.value_size (), 8);
%!   assert (m.max_entries (), 4);
%!   for k = 0:3
%!     m.update (k, 1000 + k);
%!   end
%!   assert (m.lookup (2), uint64 (1002));
%!   clear m
%! endif

%!test  % hash maps support removal and iteration
%! if (bpf.have_bpf ())
%!   m = bpf.Map.create ('hash', 4, 8, 8, 'octave_tst_hash');
%!   m.update (7, 42);
%!   assert (m.lookup (7), uint64 (42));
%!   assert (m.next_key (), uint32 (7));
%!   m.remove (7);
%!   assert (isempty (m.next_key ()));
%!   clear m
%! endif

%!test  % raw byte access
%! if (bpf.have_bpf ())
%!   m = bpf.Map.create ('array', 4, 8, 1, 'octave_tst_raw');
%!   m.update (0, uint8 (1:8));
%!   assert (m.lookup (0, 'raw'), uint8 (1:8));
%!   clear m
%! endif

%!test  % the kernel reports the map back
%! if (bpf.have_bpf ())
%!   m = bpf.Map.create ('array', 4, 4, 3, 'octave_tst_info');
%!   i = m.info ();
%!   assert (i.type, bpf.map_type ('array'));
%!   assert (i.max_entries, 3);
%!   assert (strcmp (i.name, 'octave_tst_info'));
%!   clear m
%! endif

%!test  % byte conversion helpers
%! assert (bpf.num2bytes (1, 4), uint8 ([1 0 0 0]));
%! assert (bpf.num2bytes (uint32 (258), 4), uint8 ([2 1 0 0]));
%! assert (bpf.bytes2num (uint8 ([2 1 0 0])), uint32 (258));
%! assert (double (bpf.bytes2num (uint8 ([2 1 0 0]))), 258);
%! assert (bpf.bytes2num (uint8 ([0xff 0xff 0xff 0xff]), true), int32 (-1));
%! assert (bpf.bytes2num (uint8 ([])), []);
