function [value, name] = map_type (key)
%BPF.MAP_TYPE  Resolve an eBPF map type.
%
%   T = bpf.map_type ('array')          % or 'ARRAY', 'BPF_MAP_TYPE_ARRAY', 2
%   [T, NAME] = bpf.map_type (KEY)      % also the canonical name
%
%   T is the numeric BPF_MAP_TYPE_* value.  Numeric input is passed through.
%
%   Note: Octave cannot parse 'bpf.map_type (x).field', so the name is
%   returned as a second output rather than as a struct field.

  [v, n] = bpf.enum_lookup ('bpf_map_type', key, 'BPF_MAP_TYPE');
  value = v;
  if (nargout > 1)
    name = n;
  end
end
