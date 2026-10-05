function [value, name] = link_type (key)
%BPF.LINK_TYPE  Resolve an eBPF link type (BPF_LINK_TYPE_*).
%
%   T = bpf.link_type ('tracing')
%   [T, NAME] = bpf.link_type (KEY)

  [v, n] = bpf.enum_lookup ('bpf_link_type', key, 'BPF_LINK_TYPE');
  value = v;
  if (nargout > 1)
    name = n;
  end
end
