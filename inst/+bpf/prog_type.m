function [value, name] = prog_type (key)
%BPF.PROG_TYPE  Resolve an eBPF program type.
%
%   T = bpf.prog_type ('kprobe')        % or 'KPROBE', 'BPF_PROG_TYPE_KPROBE', 2
%   [T, NAME] = bpf.prog_type (KEY)
%
%   Programs written with bpf.Builder take their type from the ELF section
%   name, so setting a program type explicitly is rarely necessary.

  [v, n] = bpf.enum_lookup ('bpf_prog_type', key, 'BPF_PROG_TYPE');
  value = v;
  if (nargout > 1)
    name = n;
  end
end
