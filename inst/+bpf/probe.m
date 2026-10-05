function tf = probe (what, arg, arg2)
%BPF.PROBE  Ask the running kernel what eBPF features it supports.
%
%   tf = bpf.probe ('prog_type', TYPE)
%   tf = bpf.probe ('map_type', TYPE)
%   tf = bpf.probe ('helper', PROG_TYPE, HELPER)
%
%   TYPE may be a name or a number.  The helper probe answers whether the
%   given program type may call the given helper.
%
%   An eBPF feature probe is performed by attempting to load a minimal
%   program, so it may take a moment.

  switch (lower (what))
    case 'prog_type'
      tf = libbpf_wrap ('probe_prog_type', bpf.prog_type (arg));
    case 'map_type'
      tf = libbpf_wrap ('probe_map_type', bpf.map_type (arg));
    case 'helper'
      tf = libbpf_wrap ('probe_helper', bpf.prog_type (arg), bpf.helper (arg2));
    otherwise
      error ('bpf:probe', 'unknown probe "%s"', what);
  end
end
