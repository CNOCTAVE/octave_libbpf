function s = get_log (mode)
%BPF.GET_LOG  Captured libbpf diagnostics.
%
%   S = bpf.get_log ()      return everything libbpf has printed so far
%   bpf.get_log ('clear')   discard the captured output

  if (nargin > 0 && strcmpi (mode, 'clear'))
    bpf.raw ('clear_log');
    if (nargout > 0)
      s = '';
    end
    return;
  end
  s = bpf.raw ('get_log');
end
