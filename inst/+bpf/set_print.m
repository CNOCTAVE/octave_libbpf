function old = set_print (level)
%BPF.SET_PRINT  Control how much libbpf prints to stderr.
%
%   OLD = bpf.set_print (LEVEL)
%
%   LEVEL is one of
%     0   silent
%     1   warnings only (the default)
%     2   warnings and informational messages
%     3   everything, including debug output
%
%   libbpf output is echoed to stderr and, independently, captured so that
%   bpf.log () can return it.  This is the easiest way to see the kernel
%   verifier log when a program is rejected.
%
%   See also bpf.log.

  if (nargin < 1)
    error ('bpf:set_print', 'usage: bpf.set_print (LEVEL)');
  end
  old = bpf.raw ('get_print_level');
  bpf.raw ('set_print_level', level);
end
