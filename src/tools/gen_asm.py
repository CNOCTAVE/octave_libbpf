#!/usr/bin/env python3
"""Generate inst/+bpf/Asm.m (the eBPF assembler class).

Keeping the mnemonic methods generated avoids ~120 hand written one-line
methods and keeps the mnemonic list in sync with bpf.Insn.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.normpath(os.path.join(HERE, '..', '..', 'inst', '+bpf'))

ALU = ['mov', 'add', 'sub', 'mul', 'div', 'or', 'and', 'lsh', 'rsh',
       'mod', 'xor', 'arsh']
MEM = ['ldx_w', 'ldx_h', 'ldx_b', 'ldx_dw', 'stx_w', 'stx_h', 'stx_b',
       'stx_dw', 'st_w', 'st_h', 'st_b', 'st_dw',
       'atomic_w', 'atomic_h', 'atomic_b', 'atomic_dw']
PKT = ['ld_abs_w', 'ld_abs_h', 'ld_abs_b', 'ld_ind_w', 'ld_ind_h', 'ld_ind_b']
JMP = ['jeq', 'jgt', 'jge', 'jset', 'jne', 'jsgt', 'jsge', 'jlt', 'jle',
       'jslt', 'jsle']
JMP32 = ['jeq', 'jne', 'jgt', 'jge', 'jlt', 'jle', 'jsgt', 'jsge', 'jslt',
         'jsle', 'jset']
SIMPLE = ['neg64', 'neg32', 'end_le', 'end_be', 'exit', 'call', 'callx',
          'ld_imm64', 'ld_btf_id', 'ld_func']

EXPLICIT = {'ld_map_fd', 'ld_map_value', 'ld_map_idx', 'label', 'jump',
            'bytes', 'relocations', 'source', 'patch', 'emit', 'count', 'ins'}


def mnemonic_names():
    names = []
    for a in ALU:
        for sz in ('64', '32'):
            for src in ('imm', 'reg'):
                names.append('%s%s_%s' % (a, sz, src))
    names += MEM + PKT + ['ja']
    for j in JMP:
        names += [j + '_imm', j + '_reg']
    for j in JMP32:
        for src in ('imm', 'reg'):
            names.append('jmp32_%s_%s' % (j, src))
    names += SIMPLE
    return names


def jump_names():
    names = ['ja']
    names += [j + '_' + s for j in JMP for s in ('imm', 'reg')]
    names += ['jmp32_%s_%s' % (j, s) for j in JMP32 for s in ('imm', 'reg')]
    return names


HEADER = r'''classdef Asm < handle
%BPF.ASM  eBPF assembler for a single program.
%
%   A = bpf.Asm ()
%
%   Collects eBPF instructions for one program, resolves symbolic branch
%   targets and records the relocations libbpf needs in order to patch map
%   references into the loaded program.
%
%   Instruction methods take the same arguments as the matching bpf.Insn
%   mnemonic.  A character string may be used in place of the branch offset
%   so that branches can refer to labels:
%
%       R = bpf.regs ();
%       a = bpf.Asm ();
%       a.ld_map_fd (R.R1, 'counts');
%       a.mov64_reg (R.R2, R.R10);
%       a.add64_imm (R.R2, -4);
%       a.call (bpf.helper ('map_lookup_elem'));
%       a.jeq_imm (R.R0, 0, 'done');
%       a.mov64_imm (R.R1, 1);
%       a.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
%       a.label ('done');
%       a.exit ();
%
%   Housekeeping methods
%   --------------------
%     a.label (NAME)          define NAME at the current instruction
%     a.jump (NAME)           unconditional branch to NAME
%     a.emit (BYTES)          append raw encoded bytes
%     a.count ()              number of instruction slots used
%     a.bytes ()              Nx8 uint8 instruction stream
%     a.relocations ()        struct array describing map relocations
%     a.source ()             human readable listing (cellstr)
%     a.patch (INDEX, BYTES)  replace the instruction at slot INDEX
%     a.ld_map_fd (DST, MAP)  load the file descriptor of a map
%     a.ld_map_value (DST, MAP, OFF)
%     a.ld_map_idx (DST, MAP)
%
%   See also bpf.Insn, bpf.Builder, bpf.regs.

  properties (Access = private)
    m_insns = zeros (0, 8, 'uint8');
    m_slots = 0;
    m_labels = [];
    m_pending = struct ('slot', {}, 'label', {}, 'base', {});
    m_relocs = struct ('slot', {}, 'sym', {}, 'kind', {});
    m_src = {};
  end

  methods

    function obj = Asm ()
      obj.m_labels = containers.Map ('KeyType', 'char', 'ValueType', 'double');
    end

    function label (obj, name)
      obj.m_labels (name) = obj.m_slots;
    end

    function jump (obj, name)
      obj.append (bpf.Insn ('ja', 0), ['ja -> ' name]);
      obj.m_pending(end+1) = struct ('slot', obj.m_slots - 1, ...
                                     'label', name, 'base', obj.m_slots);
    end

    function ld_map_fd (obj, dst, sym)
      obj.append (bpf.Insn ('ld_map_fd', dst), '');
      obj.m_relocs(end+1) = struct ('slot', obj.m_slots - 2, 'sym', sym, ...
                                    'kind', 'map_fd');
      obj.m_src{end} = sprintf ('ld_map_fd     r%d, %s', dst, sym);
    end

    function ld_map_value (obj, dst, sym, off)
      if (nargin < 4)
        off = 0;
      end
      obj.append (bpf.Insn ('ld_map_value', dst), '');
      obj.m_relocs(end+1) = struct ('slot', obj.m_slots - 2, 'sym', sym, ...
                                    'kind', 'map_value');
      obj.m_src{end} = sprintf ('ld_map_value  r%d, %s+%d', dst, sym, off);
    end

    function ld_map_idx (obj, dst, sym)
      obj.append (bpf.Insn ('ld_map_idx', dst), '');
      obj.m_relocs(end+1) = struct ('slot', obj.m_slots - 2, 'sym', sym, ...
                                    'kind', 'map_idx');
      obj.m_src{end} = sprintf ('ld_map_idx    r%d, %s', dst, sym);
    end

    function n = count (obj)
      n = obj.m_slots;
    end

    function b = bytes (obj)
      obj.resolve ();
      b = obj.m_insns;
    end

    function r = relocations (obj)
      obj.resolve ();
      r = obj.m_relocs;
      if (isempty (r))
        r = struct ('slot', {}, 'sym', {}, 'kind', {});
      end
    end

    function s = source (obj)
      s = obj.m_src;
    end

    function patch (obj, index, rawbytes)
      if (index < 0 || index >= obj.m_slots)
        error ('bpf:Asm', 'patch index out of range');
      end
      obj.m_insns(index+1, :) = rawbytes(1, :);
    end

    function emit (obj, rawbytes)
      obj.append (rawbytes, 'raw');
    end

    function o = ins (obj, name, args)
      isjump = any (strcmp (name, bpf.Asm.jump_names ()));
      if (isjump && ~ isempty (args) && ischar (args{end}))
        label = args{end};
        args{end} = 0;
        obj.append (bpf.Insn (name, args{:}), ...
                    sprintf ('%-13s -> %s', name, label));
        obj.m_pending(end+1) = struct ('slot', obj.m_slots - 1, ...
                                       'label', label, 'base', obj.m_slots);
      else
        obj.append (bpf.Insn (name, args{:}), obj.text (name, args));
      end
      o = obj;
    end
  end

  methods (Static)
    function names = jump_names ()
      names = { __JUMPNAMES__ };
    end
  end

  methods (Access = private)

    function append (obj, raw, txt)
      if (mod (numel (raw), 8) ~= 0)
        error ('bpf:Asm', 'instruction encodings must be a multiple of 8 bytes');
      end
      if (size (raw, 2) ~= 8)
        raw = reshape (raw, 8, []).';
      end
      n = size (raw, 1);
      if (n == 0)
        return;
      end
      obj.m_insns(obj.m_slots + 1 : obj.m_slots + n, :) = raw;
      obj.m_slots = obj.m_slots + n;
      if (isempty (obj.m_src))
        obj.m_src = { txt };
      else
        obj.m_src{end+1} = txt;
      end
    end

    function txt = text (obj, name, args)
      regs = obj.reg_args (name);
      parts = cell (1, numel (args));
      for k = 1:numel (args)
        v = args{k};
        if (ischar (v))
          parts{k} = v;
        elseif (any (regs == k))
          parts{k} = sprintf ('r%d', v);
        else
          parts{k} = num2str (v);
        end
      end
      txt = strtrim (sprintf ('%-13s %s', name, strjoin (parts, ', ')));
    end

    function p = reg_args (obj, name)
      % which positional arguments of NAME denote registers, for listings
      p = [];
      if (any (strcmp (name, {'exit', 'ja', 'call', 'end_le', 'end_be'})))
        return;
      end
      if (strcmp (name, 'callx'))
        p = 1;
        return;
      end
      if (numel (name) > 6 && strcmp (name(1:6), 'atomic'))
        p = [1 2];
        return;
      end
      if (numel (name) > 6 && strcmp (name(1:6), 'jmp32_'))
        if (~ isempty (strfind (name, '_reg')))
          p = [1 2];
        else
          p = 1;
        end
        return;
      end

      k = 1;
      while (k <= numel (name) && name(k) >= 'a' && name(k) <= 'z')
        k = k + 1;
      end
      pfx = name(1:k-1);

      jumps = {'jeq', 'jgt', 'jge', 'jset', 'jne', 'jsgt', 'jsge', ...
               'jlt', 'jle', 'jslt', 'jsle'};
      if (any (strcmp (pfx, jumps)))
        if (~ isempty (strfind (name, '_reg')))
          p = [1 2];
        else
          p = 1;
        end
        return;
      end

      alu = {'mov', 'add', 'sub', 'mul', 'div', 'or', 'and', 'lsh', ...
             'rsh', 'mod', 'xor', 'arsh', 'neg'};
      if (any (strcmp (pfx, alu)))
        if (strcmp (pfx, 'neg'))
          p = 1;
        elseif (~ isempty (strfind (name, '_reg')))
          p = [1 2];
        else
          p = 1;
        end
        return;
      end

      switch (pfx)
        case {'ldx', 'stx'}
          p = [1 2];
        case {'st', 'ld'}
          p = 1;
      end
    end

    function resolve (obj)
      for k = 1:numel (obj.m_pending)
        p = obj.m_pending(k);
        if (~ isKey (obj.m_labels, p.label))
          error ('bpf:Asm', 'undefined label "%s"', p.label);
        end
        rel = obj.m_labels (p.label) - p.base;
        if (rel < -32768 || rel > 32767)
          error ('bpf:Asm', 'branch to "%s" out of range', p.label);
        end
        obj.m_insns(p.slot + 1, 3:4) = typecast (int16 (rel), 'uint8');
      end
    end
  end

  %% ------------------------------------------------------------- mnemonics
  methods
'''


def main():
    jumps = jump_names()
    jump_ml = " ...\n                 ".join("'%s'" % j for j in jumps)
    out = [HEADER.replace('__JUMPNAMES__', jump_ml)]
    count = 0
    for n in mnemonic_names():
        if n in EXPLICIT:
            continue
        out.append("    function o = %s (obj, varargin)\n" % n)
        out.append("      o = obj.ins ('%s', varargin);\n" % n)
        out.append("    end\n\n")
        count += 1
    out.append("  end\nend\n")
    text = "".join(out)
    with open(os.path.join(INST, 'Asm.m'), 'w') as fh:
        fh.write(text)
    print("Asm.m: %d mnemonic methods, %d lines" % (count, text.count('\n')))


if __name__ == '__main__':
    main()
