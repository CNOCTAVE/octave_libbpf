function out = Insn (cmd, varargin)
%BPF.INSN  eBPF instruction encoder.
%
%   bytes = bpf.Insn (MNEMONIC, ...)
%
%   Encodes a single eBPF instruction (or, for the 64 bit immediate load,
%   two instructions) into a 1x8 (resp. 1x16) uint8 row vector holding the
%   little endian 'struct bpf_insn' representation.
%
%   Generic form
%   ------------
%     bpf.Insn ('raw', CODE, DST, SRC, OFF, IMM)
%
%   Arithmetic / logic  (DST OP= SRC  or  DST OP= IMM)
%   ---------------------------------------------------
%     mov64_imm  mov64_reg   mov32_imm  mov32_reg
%     add sub mul div or and lsh rsh mod xor arsh
%       ... each with the 64/32 and imm/reg combinations, e.g. add32_reg
%     neg64  neg32
%     end_le  end_be   (byte swap, second argument is the width in bits)
%
%   Memory
%   ------
%     ldx_w   ldx_h   ldx_b   ldx_dw    DST = *(SIZE *)(SRC + OFF)
%     stx_w   stx_h   stx_b   stx_dw    *(SIZE *)(DST + OFF) = SRC
%     st_w    st_h    st_b    st_dw     *(SIZE *)(DST + OFF) = IMM
%     ld_abs_w ld_abs_h ld_abs_b ld_ind_w ld_ind_h ld_ind_b
%
%   Branches  (OFF is a relative instruction offset)
%   ------------------------------------------------
%     ja  jeq_imm jeq_reg  jgt jge jset jne jsgt jsge jlt jle jslt jsle
%     jmp32_jeq_imm ... jmp32_jsle_reg
%     call IMM        callx SRC        exit
%
%   Atomics  (IMM is the BPF_ATOMIC operation)
%   ------------------------------------------
%     atomic_w  atomic_h  atomic_b  atomic_dw
%
%   Special
%   -------
%     ld_imm64     DST, IMM       (occupies two instruction slots)
%     ld_map_fd    DST            (relocated to the map file descriptor)
%     ld_map_value DST, OFF       (map value pseudo load)
%     ld_map_idx   DST
%     ld_btf_id    DST, ID
%     ld_func      DST, ID
%
%   See also bpf.Asm, bpf.regs.

  cmd = lower (cmd);

  switch cmd
    case 'raw'
      if (numel (varargin) ~= 5)
        error ('bpf:Insn', 'raw needs CODE, DST, SRC, OFF, IMM');
      end
      out = encode (varargin{1}, varargin{2}, varargin{3}, varargin{4}, varargin{5});

    case 'exit'
      out = encode (0x95, 0, 0, 0, 0);

    case 'call'
      out = encode (0x85, 0, 0, 0, varargin{1});

    case 'callx'
      out = encode (0x85, 0, varargin{1}, 0, 0);

    case 'ld_imm64'
      % a 64 bit immediate is carried in two instruction slots: the low 32
      % bits in the first immediate field, the high 32 bits in the second
      out = [ pseudo_ld(varargin{1}, 0, lo32(varargin{2})), ...
              encode(0, 0, 0, 0, hi32(varargin{2})) ];

    case 'ld_map_fd'
      out = [ pseudo_ld(varargin{1}, 1, 0), encode(0, 0, 0, 0, 0) ];

    case 'ld_map_value'
      out = [ pseudo_ld(varargin{1}, 2, 0), encode(0, 0, 0, 0, 0) ];

    case 'ld_map_idx'
      out = [ pseudo_ld(varargin{1}, 5, 0), encode(0, 0, 0, 0, 0) ];

    case 'ld_btf_id'
      out = [ pseudo_ld(varargin{1}, 3, 0), encode(0, 0, 0, 0, 0) ];

    case 'ld_func'
      out = [ pseudo_ld(varargin{1}, 4, 0), encode(0, 0, 0, 0, 0) ];

    otherwise
      out = generic (cmd, varargin{:});
  end
end

% ---------------------------------------------------------------------------

function b = encode (code, dst, src, off, imm)
  b = zeros (1, 8, 'uint8');
  b(1) = uint8 (mod (code, 256));
  b(2) = uint8 (mod (dst, 16) + 16 * mod (src, 16));
  b(3:4) = le_bytes (off, 2);
  b(5:8) = le_bytes (imm, 4);
end

function b = pseudo_ld (dst, src, imm)
  b = encode (0x18, dst, src, 0, imm);
end

function l = lo32 (v)
  v = double (v);
  if (v < 0)
    v = v + 2^64;
  end
  l = mod (v, 2^32);
end

function h = hi32 (v)
  v = double (v);
  if (v < 0)
    v = v + 2^64;
  end
  h = mod (floor (v / 2^32), 2^32);
end

function b = le_bytes (val, n)
  v = double (val);
  if (v < 0)
    v = v + 2^(8 * n);
  end
  b = zeros (1, n, 'uint8');
  for k = 1:n
    b(k) = uint8 (mod (v, 256));
    v = floor (v / 256);
  end
end

% ---------------------------------------------------------------------------

function out = generic (cmd, varargin)
  persistent alu_ops jmp_ops

  if (isempty (alu_ops))
    alu_ops = { 'add', 0x00; 'sub', 0x10; 'mul', 0x20; 'div', 0x30; ...
                'or',  0x40; 'and', 0x50; 'lsh', 0x60; 'rsh', 0x70; ...
                'neg', 0x80; 'mod', 0x90; 'xor', 0xa0; 'mov', 0xb0; ...
                'arsh', 0xc0 };
    jmp_ops = { 'ja',   0x00; 'jeq',  0x10; 'jgt',  0x20; 'jge',  0x30; ...
                'jset', 0x40; 'jne',  0x50; 'jsgt', 0x60; 'jsge', 0x70; ...
                'jlt',  0xa0; 'jle',  0xb0; 'jslt', 0xc0; 'jsle', 0xd0 };
  end

  is32jmp = false;
  c = cmd;
  if (numel (c) > 6 && strcmp (c(1:6), 'jmp32_'))
    is32jmp = true;
    c = c(7:end);
  end

  [pfx, rest] = split_prefix (c);

  % ---- explicit specials --------------------------------------------------
  if (strcmp (pfx, 'end'))
    if (strcmp (rest, 'le'))
      out = encode (0xd4, varargin{1}, 0, 0, varargin{2});
    elseif (strcmp (rest, 'be'))
      out = encode (0xdc, varargin{1}, 0, 0, varargin{2});
    else
      error ('bpf:Insn', 'unknown mnemonic ''%s''', cmd);
    end
    return;
  end

  % ---- legacy packet access ----------------------------------------------
  if (strcmp (pfx, 'ld') && numel (rest) > 4)
    if (strncmp (rest, 'abs_', 4))
      out = encode (0x00 + 0x20 + size_code (rest(5:end), cmd), 0, 0, 0, varargin{1});
      return;
    elseif (strncmp (rest, 'ind_', 4))
      out = encode (0x00 + 0x40 + size_code (rest(5:end), cmd), ...
                    0, varargin{1}, 0, varargin{2});
      return;
    end
  end

  % ---- memory and atomics -------------------------------------------------
  switch pfx
    case 'ldx'
      out = encode (0x01 + 0x60 + size_code (rest, cmd), ...
                    varargin{1}, varargin{2}, varargin{3}, 0);
      return;
    case 'stx'
      out = encode (0x03 + 0x60 + size_code (rest, cmd), ...
                    varargin{1}, varargin{2}, varargin{3}, 0);
      return;
    case 'st'
      out = encode (0x02 + 0x60 + size_code (rest, cmd), ...
                    varargin{1}, 0, varargin{2}, varargin{3});
      return;
    case 'atomic'
      out = encode (0x03 + 0xc0 + size_code (rest, cmd), ...
                    varargin{1}, varargin{2}, varargin{3}, varargin{4});
      return;
  end

  % ---- branches -----------------------------------------------------------
  [op, srcmode] = split_src (c);
  j = lookup_idx (jmp_ops, op);
  if (j > 0)
    v = jmp_ops{j, 2};
    cls = 0x05;
    if (is32jmp)
      cls = 0x06;
    end
    if (strcmp (op, 'ja'))
      out = encode (cls + v, 0, 0, varargin{1}, 0);
    elseif (strcmp (srcmode, 'reg'))
      out = encode (cls + v + 0x08, varargin{1}, varargin{2}, varargin{3}, 0);
    else
      out = encode (cls + v, varargin{1}, 0, varargin{2}, varargin{3});
    end
    return;
  end

  % ---- ALU ----------------------------------------------------------------
  aluop = regexprep (op, '(64|32)$', '');
  a = lookup_idx (alu_ops, aluop);
  if (a > 0)
    v = alu_ops{a, 2};
    if (is64 (cmd))
      cls = 0x07;
    else
      cls = 0x04;
    end
    if (strcmp (aluop, 'neg'))
      out = encode (cls + v, varargin{1}, 0, 0, 0);
    elseif (strcmp (srcmode, 'reg'))
      out = encode (cls + v + 0x08, varargin{1}, varargin{2}, 0, 0);
    else
      out = encode (cls + v, varargin{1}, 0, 0, varargin{2});
    end
    return;
  end

  error ('bpf:Insn', 'unknown mnemonic ''%s''', cmd);
end

% --- helpers ---------------------------------------------------------------

function [pfx, rest] = split_prefix (c)
  k = 1;
  while (k <= numel (c) && c(k) >= 'a' && c(k) <= 'z')
    k = k + 1;
  end
  pfx = c(1:k-1);
  rest = c(k:end);
  if (~isempty (rest) && rest(1) == '_')
    rest = rest(2:end);
  end
end

function [op, srcmode] = split_src (cmd)
  srcmode = 'imm';
  op = cmd;
  if (numel (cmd) > 4 && strcmp (cmd(end-3:end), '_imm'))
    op = cmd(1:end-4);
  elseif (numel (cmd) > 4 && strcmp (cmd(end-3:end), '_reg'))
    op = cmd(1:end-4);
    srcmode = 'reg';
  end
end

function tf = is64 (cmd)
  [~, rest] = split_prefix (cmd);
  [rest, ~] = split_src (rest);
  tf = strcmp (rest, '64');
end

function i = lookup_idx (tbl, key)
  i = 0;
  for k = 1:size (tbl, 1)
    if (strcmp (tbl{k, 1}, key))
      i = k;
      return;
    end
  end
end

function sz = size_code (sfx, cmd)
  switch (sfx)
    case 'w',  sz = 0x00;
    case 'h',  sz = 0x08;
    case 'b',  sz = 0x10;
    case 'dw', sz = 0x18;
    otherwise
      error ('bpf:Insn', 'unknown size suffix in ''%s''', cmd);
  end
end
