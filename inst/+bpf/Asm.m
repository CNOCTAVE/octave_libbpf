classdef Asm < handle
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
      names = { 'ja' ...
                 'jeq_imm' ...
                 'jeq_reg' ...
                 'jgt_imm' ...
                 'jgt_reg' ...
                 'jge_imm' ...
                 'jge_reg' ...
                 'jset_imm' ...
                 'jset_reg' ...
                 'jne_imm' ...
                 'jne_reg' ...
                 'jsgt_imm' ...
                 'jsgt_reg' ...
                 'jsge_imm' ...
                 'jsge_reg' ...
                 'jlt_imm' ...
                 'jlt_reg' ...
                 'jle_imm' ...
                 'jle_reg' ...
                 'jslt_imm' ...
                 'jslt_reg' ...
                 'jsle_imm' ...
                 'jsle_reg' ...
                 'jmp32_jeq_imm' ...
                 'jmp32_jeq_reg' ...
                 'jmp32_jne_imm' ...
                 'jmp32_jne_reg' ...
                 'jmp32_jgt_imm' ...
                 'jmp32_jgt_reg' ...
                 'jmp32_jge_imm' ...
                 'jmp32_jge_reg' ...
                 'jmp32_jlt_imm' ...
                 'jmp32_jlt_reg' ...
                 'jmp32_jle_imm' ...
                 'jmp32_jle_reg' ...
                 'jmp32_jsgt_imm' ...
                 'jmp32_jsgt_reg' ...
                 'jmp32_jsge_imm' ...
                 'jmp32_jsge_reg' ...
                 'jmp32_jslt_imm' ...
                 'jmp32_jslt_reg' ...
                 'jmp32_jsle_imm' ...
                 'jmp32_jsle_reg' ...
                 'jmp32_jset_imm' ...
                 'jmp32_jset_reg' };
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
    function o = mov64_imm (obj, varargin)
      o = obj.ins ('mov64_imm', varargin);
    end

    function o = mov64_reg (obj, varargin)
      o = obj.ins ('mov64_reg', varargin);
    end

    function o = mov32_imm (obj, varargin)
      o = obj.ins ('mov32_imm', varargin);
    end

    function o = mov32_reg (obj, varargin)
      o = obj.ins ('mov32_reg', varargin);
    end

    function o = add64_imm (obj, varargin)
      o = obj.ins ('add64_imm', varargin);
    end

    function o = add64_reg (obj, varargin)
      o = obj.ins ('add64_reg', varargin);
    end

    function o = add32_imm (obj, varargin)
      o = obj.ins ('add32_imm', varargin);
    end

    function o = add32_reg (obj, varargin)
      o = obj.ins ('add32_reg', varargin);
    end

    function o = sub64_imm (obj, varargin)
      o = obj.ins ('sub64_imm', varargin);
    end

    function o = sub64_reg (obj, varargin)
      o = obj.ins ('sub64_reg', varargin);
    end

    function o = sub32_imm (obj, varargin)
      o = obj.ins ('sub32_imm', varargin);
    end

    function o = sub32_reg (obj, varargin)
      o = obj.ins ('sub32_reg', varargin);
    end

    function o = mul64_imm (obj, varargin)
      o = obj.ins ('mul64_imm', varargin);
    end

    function o = mul64_reg (obj, varargin)
      o = obj.ins ('mul64_reg', varargin);
    end

    function o = mul32_imm (obj, varargin)
      o = obj.ins ('mul32_imm', varargin);
    end

    function o = mul32_reg (obj, varargin)
      o = obj.ins ('mul32_reg', varargin);
    end

    function o = div64_imm (obj, varargin)
      o = obj.ins ('div64_imm', varargin);
    end

    function o = div64_reg (obj, varargin)
      o = obj.ins ('div64_reg', varargin);
    end

    function o = div32_imm (obj, varargin)
      o = obj.ins ('div32_imm', varargin);
    end

    function o = div32_reg (obj, varargin)
      o = obj.ins ('div32_reg', varargin);
    end

    function o = or64_imm (obj, varargin)
      o = obj.ins ('or64_imm', varargin);
    end

    function o = or64_reg (obj, varargin)
      o = obj.ins ('or64_reg', varargin);
    end

    function o = or32_imm (obj, varargin)
      o = obj.ins ('or32_imm', varargin);
    end

    function o = or32_reg (obj, varargin)
      o = obj.ins ('or32_reg', varargin);
    end

    function o = and64_imm (obj, varargin)
      o = obj.ins ('and64_imm', varargin);
    end

    function o = and64_reg (obj, varargin)
      o = obj.ins ('and64_reg', varargin);
    end

    function o = and32_imm (obj, varargin)
      o = obj.ins ('and32_imm', varargin);
    end

    function o = and32_reg (obj, varargin)
      o = obj.ins ('and32_reg', varargin);
    end

    function o = lsh64_imm (obj, varargin)
      o = obj.ins ('lsh64_imm', varargin);
    end

    function o = lsh64_reg (obj, varargin)
      o = obj.ins ('lsh64_reg', varargin);
    end

    function o = lsh32_imm (obj, varargin)
      o = obj.ins ('lsh32_imm', varargin);
    end

    function o = lsh32_reg (obj, varargin)
      o = obj.ins ('lsh32_reg', varargin);
    end

    function o = rsh64_imm (obj, varargin)
      o = obj.ins ('rsh64_imm', varargin);
    end

    function o = rsh64_reg (obj, varargin)
      o = obj.ins ('rsh64_reg', varargin);
    end

    function o = rsh32_imm (obj, varargin)
      o = obj.ins ('rsh32_imm', varargin);
    end

    function o = rsh32_reg (obj, varargin)
      o = obj.ins ('rsh32_reg', varargin);
    end

    function o = mod64_imm (obj, varargin)
      o = obj.ins ('mod64_imm', varargin);
    end

    function o = mod64_reg (obj, varargin)
      o = obj.ins ('mod64_reg', varargin);
    end

    function o = mod32_imm (obj, varargin)
      o = obj.ins ('mod32_imm', varargin);
    end

    function o = mod32_reg (obj, varargin)
      o = obj.ins ('mod32_reg', varargin);
    end

    function o = xor64_imm (obj, varargin)
      o = obj.ins ('xor64_imm', varargin);
    end

    function o = xor64_reg (obj, varargin)
      o = obj.ins ('xor64_reg', varargin);
    end

    function o = xor32_imm (obj, varargin)
      o = obj.ins ('xor32_imm', varargin);
    end

    function o = xor32_reg (obj, varargin)
      o = obj.ins ('xor32_reg', varargin);
    end

    function o = arsh64_imm (obj, varargin)
      o = obj.ins ('arsh64_imm', varargin);
    end

    function o = arsh64_reg (obj, varargin)
      o = obj.ins ('arsh64_reg', varargin);
    end

    function o = arsh32_imm (obj, varargin)
      o = obj.ins ('arsh32_imm', varargin);
    end

    function o = arsh32_reg (obj, varargin)
      o = obj.ins ('arsh32_reg', varargin);
    end

    function o = ldx_w (obj, varargin)
      o = obj.ins ('ldx_w', varargin);
    end

    function o = ldx_h (obj, varargin)
      o = obj.ins ('ldx_h', varargin);
    end

    function o = ldx_b (obj, varargin)
      o = obj.ins ('ldx_b', varargin);
    end

    function o = ldx_dw (obj, varargin)
      o = obj.ins ('ldx_dw', varargin);
    end

    function o = stx_w (obj, varargin)
      o = obj.ins ('stx_w', varargin);
    end

    function o = stx_h (obj, varargin)
      o = obj.ins ('stx_h', varargin);
    end

    function o = stx_b (obj, varargin)
      o = obj.ins ('stx_b', varargin);
    end

    function o = stx_dw (obj, varargin)
      o = obj.ins ('stx_dw', varargin);
    end

    function o = st_w (obj, varargin)
      o = obj.ins ('st_w', varargin);
    end

    function o = st_h (obj, varargin)
      o = obj.ins ('st_h', varargin);
    end

    function o = st_b (obj, varargin)
      o = obj.ins ('st_b', varargin);
    end

    function o = st_dw (obj, varargin)
      o = obj.ins ('st_dw', varargin);
    end

    function o = atomic_w (obj, varargin)
      o = obj.ins ('atomic_w', varargin);
    end

    function o = atomic_h (obj, varargin)
      o = obj.ins ('atomic_h', varargin);
    end

    function o = atomic_b (obj, varargin)
      o = obj.ins ('atomic_b', varargin);
    end

    function o = atomic_dw (obj, varargin)
      o = obj.ins ('atomic_dw', varargin);
    end

    function o = ld_abs_w (obj, varargin)
      o = obj.ins ('ld_abs_w', varargin);
    end

    function o = ld_abs_h (obj, varargin)
      o = obj.ins ('ld_abs_h', varargin);
    end

    function o = ld_abs_b (obj, varargin)
      o = obj.ins ('ld_abs_b', varargin);
    end

    function o = ld_ind_w (obj, varargin)
      o = obj.ins ('ld_ind_w', varargin);
    end

    function o = ld_ind_h (obj, varargin)
      o = obj.ins ('ld_ind_h', varargin);
    end

    function o = ld_ind_b (obj, varargin)
      o = obj.ins ('ld_ind_b', varargin);
    end

    function o = ja (obj, varargin)
      o = obj.ins ('ja', varargin);
    end

    function o = jeq_imm (obj, varargin)
      o = obj.ins ('jeq_imm', varargin);
    end

    function o = jeq_reg (obj, varargin)
      o = obj.ins ('jeq_reg', varargin);
    end

    function o = jgt_imm (obj, varargin)
      o = obj.ins ('jgt_imm', varargin);
    end

    function o = jgt_reg (obj, varargin)
      o = obj.ins ('jgt_reg', varargin);
    end

    function o = jge_imm (obj, varargin)
      o = obj.ins ('jge_imm', varargin);
    end

    function o = jge_reg (obj, varargin)
      o = obj.ins ('jge_reg', varargin);
    end

    function o = jset_imm (obj, varargin)
      o = obj.ins ('jset_imm', varargin);
    end

    function o = jset_reg (obj, varargin)
      o = obj.ins ('jset_reg', varargin);
    end

    function o = jne_imm (obj, varargin)
      o = obj.ins ('jne_imm', varargin);
    end

    function o = jne_reg (obj, varargin)
      o = obj.ins ('jne_reg', varargin);
    end

    function o = jsgt_imm (obj, varargin)
      o = obj.ins ('jsgt_imm', varargin);
    end

    function o = jsgt_reg (obj, varargin)
      o = obj.ins ('jsgt_reg', varargin);
    end

    function o = jsge_imm (obj, varargin)
      o = obj.ins ('jsge_imm', varargin);
    end

    function o = jsge_reg (obj, varargin)
      o = obj.ins ('jsge_reg', varargin);
    end

    function o = jlt_imm (obj, varargin)
      o = obj.ins ('jlt_imm', varargin);
    end

    function o = jlt_reg (obj, varargin)
      o = obj.ins ('jlt_reg', varargin);
    end

    function o = jle_imm (obj, varargin)
      o = obj.ins ('jle_imm', varargin);
    end

    function o = jle_reg (obj, varargin)
      o = obj.ins ('jle_reg', varargin);
    end

    function o = jslt_imm (obj, varargin)
      o = obj.ins ('jslt_imm', varargin);
    end

    function o = jslt_reg (obj, varargin)
      o = obj.ins ('jslt_reg', varargin);
    end

    function o = jsle_imm (obj, varargin)
      o = obj.ins ('jsle_imm', varargin);
    end

    function o = jsle_reg (obj, varargin)
      o = obj.ins ('jsle_reg', varargin);
    end

    function o = jmp32_jeq_imm (obj, varargin)
      o = obj.ins ('jmp32_jeq_imm', varargin);
    end

    function o = jmp32_jeq_reg (obj, varargin)
      o = obj.ins ('jmp32_jeq_reg', varargin);
    end

    function o = jmp32_jne_imm (obj, varargin)
      o = obj.ins ('jmp32_jne_imm', varargin);
    end

    function o = jmp32_jne_reg (obj, varargin)
      o = obj.ins ('jmp32_jne_reg', varargin);
    end

    function o = jmp32_jgt_imm (obj, varargin)
      o = obj.ins ('jmp32_jgt_imm', varargin);
    end

    function o = jmp32_jgt_reg (obj, varargin)
      o = obj.ins ('jmp32_jgt_reg', varargin);
    end

    function o = jmp32_jge_imm (obj, varargin)
      o = obj.ins ('jmp32_jge_imm', varargin);
    end

    function o = jmp32_jge_reg (obj, varargin)
      o = obj.ins ('jmp32_jge_reg', varargin);
    end

    function o = jmp32_jlt_imm (obj, varargin)
      o = obj.ins ('jmp32_jlt_imm', varargin);
    end

    function o = jmp32_jlt_reg (obj, varargin)
      o = obj.ins ('jmp32_jlt_reg', varargin);
    end

    function o = jmp32_jle_imm (obj, varargin)
      o = obj.ins ('jmp32_jle_imm', varargin);
    end

    function o = jmp32_jle_reg (obj, varargin)
      o = obj.ins ('jmp32_jle_reg', varargin);
    end

    function o = jmp32_jsgt_imm (obj, varargin)
      o = obj.ins ('jmp32_jsgt_imm', varargin);
    end

    function o = jmp32_jsgt_reg (obj, varargin)
      o = obj.ins ('jmp32_jsgt_reg', varargin);
    end

    function o = jmp32_jsge_imm (obj, varargin)
      o = obj.ins ('jmp32_jsge_imm', varargin);
    end

    function o = jmp32_jsge_reg (obj, varargin)
      o = obj.ins ('jmp32_jsge_reg', varargin);
    end

    function o = jmp32_jslt_imm (obj, varargin)
      o = obj.ins ('jmp32_jslt_imm', varargin);
    end

    function o = jmp32_jslt_reg (obj, varargin)
      o = obj.ins ('jmp32_jslt_reg', varargin);
    end

    function o = jmp32_jsle_imm (obj, varargin)
      o = obj.ins ('jmp32_jsle_imm', varargin);
    end

    function o = jmp32_jsle_reg (obj, varargin)
      o = obj.ins ('jmp32_jsle_reg', varargin);
    end

    function o = jmp32_jset_imm (obj, varargin)
      o = obj.ins ('jmp32_jset_imm', varargin);
    end

    function o = jmp32_jset_reg (obj, varargin)
      o = obj.ins ('jmp32_jset_reg', varargin);
    end

    function o = neg64 (obj, varargin)
      o = obj.ins ('neg64', varargin);
    end

    function o = neg32 (obj, varargin)
      o = obj.ins ('neg32', varargin);
    end

    function o = end_le (obj, varargin)
      o = obj.ins ('end_le', varargin);
    end

    function o = end_be (obj, varargin)
      o = obj.ins ('end_be', varargin);
    end

    function o = exit (obj, varargin)
      o = obj.ins ('exit', varargin);
    end

    function o = call (obj, varargin)
      o = obj.ins ('call', varargin);
    end

    function o = callx (obj, varargin)
      o = obj.ins ('callx', varargin);
    end

    function o = ld_imm64 (obj, varargin)
      o = obj.ins ('ld_imm64', varargin);
    end

    function o = ld_btf_id (obj, varargin)
      o = obj.ins ('ld_btf_id', varargin);
    end

    function o = ld_func (obj, varargin)
      o = obj.ins ('ld_func', varargin);
    end

  end
end
