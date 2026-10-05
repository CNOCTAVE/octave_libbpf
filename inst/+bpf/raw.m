function varargout = raw (cmd, varargin)
%BPF.RAW  Call the underlying libbpf oct-file directly.
%
%   [A, B, ...] = bpf.raw (COMMAND, ARG, ...)
%   bpf.raw (COMMAND, ARG, ...)              % no output wanted
%
%   This is the escape hatch to the complete libbpf binding.  COMMAND is one
%   of the command names accepted by the 'libbpf_wrap' oct-file; run
%
%       bpf.commands ()
%
%   for the list.  Pointers are passed and returned as uint64 scalars.  The
%   class hierarchy (bpf.Object, bpf.Program, ...) is built on top of this
%   function.
%
%   Example
%   -------
%       fd = bpf.raw ('map_create', bpf.map_type ('array'),
%                     'mymap', 4, 8, 16, struct ());
%       bpf.raw ('map_update_fd', fd, uint8 ([0 0 0 0]),
%                bpf.num2bytes (1234, 8), 0);
%
%   See also bpf.commands, libbpf_wrap.

  if (nargout == 0)
    libbpf_wrap (cmd, varargin{:});
    return;
  end
  [varargout{1:nargout}] = libbpf_wrap (cmd, varargin{:});
end
