function v = version ()
%BPF.VERSION  Version of the libbpf library in use.
%
%   V = bpf.version () returns a struct with fields 'major', 'minor' and
%   'string'.

  v = libbpf_wrap ('version');
end
