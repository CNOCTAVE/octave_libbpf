%TST_MISC  Version, enumeration and probing helpers.

%!test  % libbpf version is reported
%! v = bpf.version ();
%! assert (v.major, 1);
%! assert (v.minor >= 0);
%! assert (ischar (v.string));

%!test  % the command list is complete and sorted
%! c = bpf.commands ();
%! assert (iscellstr (c));
%! assert (numel (c) > 100);
%! assert (strcmp (c{1}, sort (c){1}));
%! assert (any (strcmp (c, 'object_load')));

%!test  % pointer conventions
%! assert (isstruct (bpf.raw ('version')));

%!test  % enumeration lookups accept names and numbers
%! assert (bpf.map_type (2), 2);
%! [v, n] = bpf.map_type (2);
%! assert (v, 2);
%! assert (strcmp (n, 'BPF_MAP_TYPE_ARRAY'));
%! assert (bpf.map_type ('ringbuf'), 27);
%! assert (bpf.prog_type ('xdp'), 6);
%! assert (bpf.link_type ('tracing') > 0);
%! fail ('bpf.map_type (''not_a_map_type'')', 'unknown bpf_map_type name');

%!test  % register table
%! R = bpf.regs ();
%! assert (R.R0, 0);
%! assert (R.R10, 10);
%! assert (R.FP, 10);

%!test  % helper table completeness
%! assert (numel (fieldnames (bpf.helper_table ())) > 200);
%! assert (bpf.helper (1), 1);

%!test  % log capture can be enabled and cleared
%! bpf.capture (true);
%! bpf.get_log ('clear');
%! assert (ischar (bpf.get_log ()));

%!test  % number of cpus
%! assert (bpf.num_cpus () >= 1);
