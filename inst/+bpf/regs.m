function R = regs ()
%BPF.REGS  eBPF register numbers.
%
%   R = bpf.regs ();
%
%   Returns a struct with the eleven eBPF registers R0 .. R10 so that
%   assembler code can be written readably:
%
%       R = bpf.regs ();
%       a.mov64_reg (R.R1, R.R10)
%
%   R0      return value
%   R1..R5  function arguments / scratch
%   R6..R9  callee saved
%   R10     read only frame pointer

  R = struct ('R0', 0, 'R1', 1, 'R2', 2, 'R3', 3, 'R4', 4, 'R5', 5, ...
              'R6', 6, 'R7', 7, 'R8', 8, 'R9', 9, 'R10', 10, ...
              'FP', 10, 'RET', 0);
end
