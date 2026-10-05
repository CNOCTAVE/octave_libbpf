function op = atomic_op (key, fetch)
%BPF.ATOMIC_OP  Resolve the immediate operand of an atomic instruction.
%
%   op = bpf.atomic_op ('add')          % BPF_ADD | BPF_FETCH
%   op = bpf.atomic_op ('add', false)   % BPF_ADD without fetch
%   op = bpf.atomic_op ('xchg')         % BPF_XCHG
%   op = bpf.atomic_op ('cmpxchg')
%
%   Use with the assembler:
%
%       a.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));

  if (nargin < 2)
    fetch = true;
  end

  switch (lower (key))
    case 'add',  base = 0x00;
    case 'or',   base = 0x40;
    case 'and',  base = 0x50;
    case 'xor',  base = 0xa0;
    case 'xchg', base = 0xe0; fetch = false;
    case 'cmpxchg', base = 0xf0; fetch = false;
    otherwise
      error ('bpf:atomic_op', 'unknown atomic operation ''%s''', key);
  end

  % Octave parses hexadecimal literals as the narrowest unsigned integer
  % type, so cast explicitly: the immediate field is a plain integer.
  op = double (base);
  if (fetch)
    op = op + double (0x01);   % BPF_FETCH
  end
end
