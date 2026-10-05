function [value, name] = attach_type (key)
%BPF.ATTACH_TYPE  Resolve an eBPF attach type.
%
%   T = bpf.attach_type ('cgroup_inet_ingress')
%   [T, NAME] = bpf.attach_type (KEY)

  [v, n] = bpf.enum_lookup ('bpf_attach_type', key, 'BPF_');
  value = v;
  if (nargout > 1)
    name = n;
  end
end
