classdef Elf < handle
%BPF.ELF  Minimal ELF64/BPF relocatable object writer.
%
%   E = bpf.Elf ()
%
%   Assembles the ELF image that libbpf expects for an eBPF object: a
%   64 bit little endian ET_REL file for EM_BPF (247) with a section header
%   table, a symbol table, an optional .BTF section and one SHT_REL section
%   per program section that references a map.
%
%   Sections
%   --------
%     idx = E.add_section (NAME, TYPE, FLAGS, ALIGN, DATA)
%     E.add_relocs (TARGET_IDX, ENTRIES)
%
%   ENTRIES is a struct array with fields 'offset' (byte offset inside the
%   target section), 'sym' (1 based symbol index) and 'type' (an R_BPF_*
%   relocation type, see bpf.Elf.R_BPF_64_64).
%
%   Symbols are added with E.add_symbol (NAME, VALUE, SIZE, INFO, SHNDX,
%   OTHER) and must be listed with all local symbols first; E.set_symbols
%   replaces the whole table.
%
%   b = E.bytes () returns the complete ELF image as a uint8 row vector.
%
%   See also bpf.Builder, bpf.Btf.

  properties (Constant)
    SHT_NULL = 0;
    SHT_PROGBITS = 1;
    SHT_SYMTAB = 2;
    SHT_STRTAB = 3;
    SHT_RELA = 4;
    SHT_NOBITS = 8;
    SHT_REL = 9;

    SHF_WRITE = 1;
    SHF_ALLOC = 2;
    SHF_EXECINSTR = 4;
    SHF_INFO_LINK = 64;

    STB_LOCAL = 0;
    STB_GLOBAL = 1;
    STB_WEAK = 2;

    STT_NOTYPE = 0;
    STT_OBJECT = 1;
    STT_FUNC = 2;
    STT_SECTION = 3;
    STT_FILE = 4;

    R_BPF_NONE = 0;
    R_BPF_64_64 = 1;
    R_BPF_64_ABS64 = 2;
    R_BPF_64_ABS32 = 3;
    R_BPF_64_NODYLD32 = 4;
    R_BPF_64_32 = 10;

    EM_BPF = 247;
    ET_REL = 1;
  end

  properties (Access = private)
    m_secs = struct ('name', {}, 'type', {}, 'flags', {}, 'align', {}, ...
                     'data', {}, 'link', {}, 'info', {}, 'entsize', {}, ...
                     'nobits', {});
    m_syms = struct ('name', {}, 'value', {}, 'size', {}, 'info', {}, ...
                     'other', {}, 'shndx', {});
    m_rels = {};        % cell array of struct('target', idx, 'entries', ...)
  end

  methods

    function idx = add_section (obj, name, type, flags, align, data, varargin)
      if (nargin < 6 || isempty (data))
        data = uint8 ([]);
      end
      nobits = (type == obj.SHT_NOBITS);
      obj.m_secs(end+1) = struct ('name', name, 'type', type, ...
                                  'flags', flags, 'align', max (align, 1), ...
                                  'data', data(:)', 'link', 0, 'info', 0, ...
                                  'entsize', 0, 'nobits', nobits);
      idx = obj.section_index (name);
    end

    function idx = section_index (obj, name)
      base = 3;   % 0 = NULL, 1 = .strtab, 2 = .shstrtab
      idx = 0;
      for k = 1:numel (obj.m_secs)
        if (strcmp (obj.m_secs(k).name, name))
          idx = base + k - 1;
        end
      end
      if (idx == 0)
        error ('bpf:Elf', 'no such section: %s', name);
      end
    end

    function add_relocs (obj, target, entries)
      if (isempty (entries))
        return;
      end
      obj.m_rels{end+1} = struct ('target', target, 'entries', entries);
    end

    function n = num_sections (obj)
      n = numel (obj.m_secs);
    end

    function add_symbol (obj, name, value, size, info, shndx, other)
      if (nargin < 7 || isempty (other))
        other = 0;
      end
      obj.m_syms(end+1) = struct ('name', name, 'value', value, ...
                                  'size', size, 'info', info, ...
                                  'other', other, 'shndx', shndx);
    end

    function s = symbols (obj)
      s = obj.m_syms;
    end

    function set_symbols (obj, syms)
      obj.m_syms = syms;
    end

    function b = bytes (obj)
      nuser = numel (obj.m_secs);
      strtab_idx = 1;
      shstrtab_idx = 2;
      symtab_idx = 3 + nuser;
      nrel = numel (obj.m_rels);
      total = symtab_idx + 1 + nrel;

      % --- string tables -------------------------------------------------
      symnames = uint8 (0);
      symoff = zeros (1, numel (obj.m_syms));
      for k = 1:numel (obj.m_syms)
        symoff(k) = numel (symnames);
        symnames = [symnames, uint8(obj.m_syms(k).name), uint8(0)];
      end

      secnames = uint8 (0);
      nameoff = zeros (1, total);
      allnames = [{'.strtab'}, {'.shstrtab'}, ...
                  {obj.m_secs.name}, {'.symtab'}];
      for k = 1:nrel
        allnames{end+1} = ['.rel' obj.m_secs(obj.m_rels{k}.target - 3 + 1).name];
      end
      for k = 1:numel (allnames)
        nameoff(k) = numel (secnames);
        secnames = [secnames, uint8(allnames{k}), uint8(0)];
      end

      % --- symbol table --------------------------------------------------
      symdata = uint8 ([]);
      symdata = [symdata, zeros(1, 24, 'uint8')];    % symbol 0
      nlocal = 1;
      for k = 1:numel (obj.m_syms)
        s = obj.m_syms(k);
        symdata = [symdata, lebytes(symoff(k), 4), uint8(s.info), ...
                   uint8(s.other), lebytes(s.shndx, 2), ...
                   lebytes(s.value, 8), lebytes(s.size, 8)];
        if (bitshift (s.info, -4) == obj.STB_LOCAL)
          nlocal = k + 1;
        end
      end

      % --- relocation sections -------------------------------------------
      reldata = cell (1, nrel);
      for k = 1:nrel
        e = obj.m_rels{k}.entries;
        d = uint8 ([]);
        for j = 1:numel (e)
          info = double (e(j).sym) * 2^32 + double (e(j).type);
          d = [d, lebytes(e(j).offset, 8), lebytes(info, 8)];
        end
        reldata{k} = d;
      end

      % --- section header table ------------------------------------------
      headers = cell (1, total);
      offset = 64;   % ELF header

      bodies = cell (1, total);
      al = zeros (1, total);
      types = zeros (1, total);
      flags = zeros (1, total);
      links = zeros (1, total);
      infos = zeros (1, total);
      entsz = zeros (1, total);

      al(strtab_idx + 1) = 1;
      types(strtab_idx + 1) = obj.SHT_STRTAB;
      bodies{strtab_idx + 1} = symnames;

      al(shstrtab_idx + 1) = 1;
      types(shstrtab_idx + 1) = obj.SHT_STRTAB;
      bodies{shstrtab_idx + 1} = secnames;

      for k = 1:nuser
        s = obj.m_secs(k);
        i = 3 + k;      % 1 based index into the tables
        al(i) = s.align;
        types(i) = s.type;
        flags(i) = s.flags;
        links(i) = s.link;
        infos(i) = s.info;
        entsz(i) = s.entsize;
        bodies{i} = s.data;
        if (s.nobits)
          bodies{i} = uint8 ([]);
        end
      end

      al(symtab_idx + 1) = 8;
      types(symtab_idx + 1) = obj.SHT_SYMTAB;
      links(symtab_idx + 1) = strtab_idx;
      infos(symtab_idx + 1) = nlocal;
      entsz(symtab_idx + 1) = 24;
      bodies{symtab_idx + 1} = symdata;

      for k = 1:nrel
        i = symtab_idx + k + 1;
        al(i) = 8;
        types(i) = obj.SHT_REL;
        flags(i) = obj.SHF_INFO_LINK;
        links(i) = symtab_idx;
        infos(i) = obj.m_rels{k}.target;
        entsz(i) = 16;
        bodies{i} = reldata{k};
      end

      % --- lay out -------------------------------------------------------
      image = uint8 (zeros (1, 64));
      for i = 2:total
        a = max (al(i), 1);
        offset = ceil (offset / a) * a;
        sz = numel (bodies{i});
        if (sz > 0)
          image(offset + 1 : offset + sz) = bodies{i};
        end
        obj.m_offsets(i) = offset;
        obj.m_sizes(i) = sz;
        offset = offset + sz;
      end

      shoff = ceil (offset / 8) * 8;
      need = shoff + total * 64;
      if (numel (image) < need)
        image(1, need) = uint8 (0);
      end

      % section 0: all zero
      for i = 2:total
        off = shoff + (i - 1) * 64;
        hdr = [lebytes(nameoff(i - 1), 4), lebytes(types(i), 4), ...
               lebytes(flags(i), 8), lebytes(0, 8), ...
               lebytes(obj.m_offsets(i), 8), lebytes(obj.m_sizes(i), 8), ...
               lebytes(links(i), 4), lebytes(infos(i), 4), ...
               lebytes(al(i), 8), lebytes(entsz(i), 8)];
        image(off + 1 : off + 64) = hdr;
      end

      % --- ELF header ----------------------------------------------------
      ident = [uint8(127), uint8('E'), uint8('L'), uint8('F'), ...
               uint8(2), uint8(1), uint8(1), uint8(0), ...
               zeros(1, 8, 'uint8')];
      ehdr = [ident, lebytes(obj.ET_REL, 2), lebytes(obj.EM_BPF, 2), ...
              lebytes(1, 4), lebytes(0, 8), lebytes(0, 8), ...
              lebytes(shoff, 8), lebytes(0, 4), lebytes(64, 2), ...
              lebytes(0, 2), lebytes(0, 2), lebytes(64, 2), ...
              lebytes(total, 2), lebytes(shstrtab_idx, 2)];
      image(1:64) = ehdr;

      b = image;
    end
  end

  properties (Access = private)
    m_offsets = [];
    m_sizes = [];
  end
end

% ---------------------------------------------------------------------------

function b = lebytes (val, n)
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
