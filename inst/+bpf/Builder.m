classdef Builder < handle
%BPF.BUILDER  Author eBPF programs and maps in Octave.
%
%   B = bpf.Builder ()            % license defaults to 'GPL'
%   B = bpf.Builder (LICENSE)
%
%   A builder collects the maps and programs of one eBPF object and turns
%   them into an ELF64/BPF image (with BTF describing the maps) that libbpf
%   can verify, load and attach.  No C compiler is involved.
%
%   Example
%   -------
%       pkg load octave_libbpf
%       R = bpf.regs ();
%
%       b = bpf.Builder ('GPL');
%       counts = b.map ('counts', 'array', 'u32', 'u64', 8);
%
%       p = b.program ('kprobe/do_sys_openat2', 'count_open');
%       p.st_w (R.R10, -4, 0);            % *(u32 *)(fp - 4) = 0
%       p.ld_map_fd (R.R1, 'counts');
%       p.mov64_reg (R.R2, R.R10);
%       p.add64_imm (R.R2, -4);
%       p.call (bpf.helper ('map_lookup_elem'));
%       p.jeq_imm (R.R0, 0, 'done');
%       p.mov64_imm (R.R1, 1);
%       p.atomic_dw (R.R0, R.R1, 0, bpf.atomic_op ('add'));
%       p.label ('done');
%       p.mov64_imm (R.R0, 0);
%       p.exit ();
%
%       obj = b.build ();                 % bpf.Object, opened from memory
%       obj.load ();
%       link = obj.attach ();             % kprobe attached
%
%       obj.find_map ('counts').lookup (0)
%
%   Methods
%   -------
%     m = B.map (NAME, TYPE, KEYTYPE, VALUETYPE, MAXENTRIES, OPTS)
%     p = B.program (SECTION, NAME)
%     b = B.elf ()                 the generated ELF image (uint8 row vector)
%     o = B.object ()              bpf.Object opened from the image
%     s = B.source ()              listing of all programs
%     B.write (PATH)               write the ELF image to a file
%
%   Type specifications for map keys and values
%   -------------------------------------------
%     'u8' 'u16' 'u32' 'u64' 's8' 's16' 's32' 's64' 'char' 'bool'
%     'ptr'                        a void pointer
%     N                            an opaque N byte value
%     struct ('btf', ID)           an already added bpf.BtfBuilder type id
%     a cell array, e.g. {'u32','u64'} for a two field struct
%
%   See also bpf.Asm, bpf.Elf, bpf.BtfBuilder, bpf.Object.

  properties
    license = 'GPL';
    log_level = 0;
    relax = false;
  end

  properties (Access = private)
    m_maps = {};      % cell array of bpf.MapDef
    m_progs = {};     % cell array of struct ('name', 'section', 'asm')
    m_base = [];      % base BTF type ids
    m_btf = [];
    m_elf_image = [];
  end

  methods

    function obj = Builder (license)
      if (nargin > 0 && ~ isempty (license))
        obj.license = license;
      end
    end

    % ------------------------------------------------------------------ map
    function m = map (obj, name, type, keytype, valtype, maxentries, opts)
      if (nargin < 4 || isempty (keytype))
        keytype = 'u32';
      end
      if (nargin < 5 || isempty (valtype))
        valtype = 'u64';
      end
      if (nargin < 6 || isempty (maxentries))
        maxentries = 1;
      end
      m = bpf.MapDef (name, type, keytype, valtype, maxentries);
      if (nargin > 6 && ~ isempty (opts))
        f = fieldnames (opts);
        for k = 1:numel (f)
          m.(f{k}) = opts.(f{k});
        end
      end
      obj.m_maps{end+1} = m;
      obj.m_elf_image = [];
    end

    function m = find_map (obj, name)
      m = [];
      for k = 1:numel (obj.m_maps)
        if (strcmp (obj.m_maps{k}.name, name))
          m = obj.m_maps{k};
          return;
        end
      end
      error ('bpf:Builder', 'no such map: %s', name);
    end

    function n = map_names (obj)
      n = cell (1, numel (obj.m_maps));
      for k = 1:numel (obj.m_maps)
        n{k} = obj.m_maps{k}.name;
      end
    end

    % -------------------------------------------------------------- program
    function p = program (obj, section, name)
      if (nargin < 3 || isempty (name))
        name = regexprep (section, '[^A-Za-z0-9_]', '_');
      end
      p = bpf.Asm ();
      obj.m_progs{end+1} = struct ('name', name, 'section', section, 'asm', p);
      obj.m_elf_image = [];
    end

    function p = prog (obj, varargin)
      p = obj.program (varargin{:});
    end

    function s = program_names (obj)
      s = cell (1, numel (obj.m_progs));
      for k = 1:numel (obj.m_progs)
        s{k} = obj.m_progs{k}.name;
      end
    end

    % --------------------------------------------------------------- output
    function b = elf (obj)
      if (isempty (obj.m_elf_image))
        obj.m_elf_image = obj.assemble ();
      end
      b = obj.m_elf_image;
    end

    function o = object (obj, varargin)
      o = bpf.Object.from_mem (obj.elf (), varargin{:});
    end

    function o = build (obj, varargin)
      o = obj.object (varargin{:});
    end

    function write (obj, path)
      fid = fopen (path, 'wb');
      if (fid < 0)
        error ('bpf:Builder', 'cannot write %s', path);
      end
      fwrite (fid, obj.elf (), 'uint8');
      fclose (fid);
    end

    function s = source (obj)
      s = {};
      for k = 1:numel (obj.m_progs)
        pr = obj.m_progs{k};
        s{end+1} = sprintf ('; ---- section %s, program %s ----', ...
                            pr.section, pr.name);
        listing = pr.asm.source ();
        for j = 1:numel (listing)
          s{end+1} = sprintf ('; %s', listing{j});
        end
      end
    end
  end

  methods (Access = private)

    % ------------------------------------------------------- base BTF types
    function ids = base_types (obj)
      if (~ isempty (obj.m_base))
        ids = obj.m_base;
        return;
      end
      B = obj.m_btf;
      ids = struct ();
      ids.u8  = B.add_int ('unsigned char', 1, 0);
      ids.u16 = B.add_int ('unsigned short', 2, 0);
      ids.u32 = B.add_int ('unsigned int', 4, 0);
      ids.u64 = B.add_int ('unsigned long long', 8, 0);
      ids.s8  = B.add_int ('signed char', 1, B.ENC_SIGNED);
      ids.s16 = B.add_int ('short', 2, B.ENC_SIGNED);
      ids.s32 = B.add_int ('int', 4, B.ENC_SIGNED);
      ids.s64 = B.add_int ('long long', 8, B.ENC_SIGNED);
      ids.char = B.add_int ('char', 1, B.ENC_CHAR);
      ids.bool = B.add_int ('_Bool', 1, B.ENC_BOOL);
      obj.m_base = ids;
    end

    function id = type_id (obj, spec)
      ids = obj.m_base;
      B = obj.m_btf;
      if (ischar (spec))
        switch (lower (spec))
          case {'u8', 'uint8', '__u8'},   id = ids.u8;
          case {'u16', 'uint16', '__u16'}, id = ids.u16;
          case {'u32', 'uint32', '__u32'}, id = ids.u32;
          case {'u64', 'uint64', '__u64'}, id = ids.u64;
          case {'s8', 'int8', '__s8'},    id = ids.s8;
          case {'s16', 'int16', '__s16'}, id = ids.s16;
          case {'s32', 'int32', '__s32'}, id = ids.s32;
          case {'s64', 'int64', '__s64'}, id = ids.s64;
          case 'char',                    id = ids.char;
          case {'bool', '_bool'},         id = ids.bool;
          case {'void', 'none'},          id = 0;
          case {'ptr', 'pointer'},        id = B.add_ptr (0);
          otherwise
            error ('bpf:Builder', 'unknown type specification ''%s''', spec);
        end
      elseif (isnumeric (spec) && isscalar (spec))
        if (spec <= 0)
          id = 0;
        else
          % an opaque value of SPEC bytes
          arr = B.add_array (ids.u8, spec, ids.u32);
          id = arr;
        end
      elseif (iscell (spec))
        members = struct ('name', {}, 'type', {});
        for k = 1:numel (spec)
          members(k).name = sprintf ('f%d', k);
          members(k).type = obj.type_id (spec{k});
        end
        id = B.add_struct ('', members);
      elseif (isstruct (spec) && isfield (spec, 'btf'))
        id = spec.btf;
      else
        error ('bpf:Builder', 'unsupported type specification');
      end
    end

    % --------------------------------------------------- map BTF structure
    function sid = map_struct (obj, m)
      ids = obj.m_base;
      B = obj.m_btf;

      m.key_type_id = obj.type_id (m.key);
      m.value_type_id = obj.type_id (m.value);

      members = struct ('name', {}, 'type', {});

      members = obj.push_member (members, 'type', B.add_ptr ( ...
                       B.add_array (ids.s32, m.type, ids.u32)));
      members = obj.push_member (members, 'max_entries', B.add_ptr ( ...
                       B.add_array (ids.s32, m.max_entries, ids.u32)));
      if (m.map_flags ~= 0)
        members = obj.push_member (members, 'map_flags', B.add_ptr ( ...
                         B.add_array (ids.s32, m.map_flags, ids.u32)));
      end
      if (m.numa_node ~= 0)
        members = obj.push_member (members, 'numa_node', B.add_ptr ( ...
                         B.add_array (ids.s32, m.numa_node, ids.u32)));
      end
      if (~ isempty (m.key_size))
        members = obj.push_member (members, 'key_size', B.add_ptr ( ...
                         B.add_array (ids.s32, m.key_size, ids.u32)));
      end
      if (~ isempty (m.value_size))
        members = obj.push_member (members, 'value_size', B.add_ptr ( ...
                         B.add_array (ids.s32, m.value_size, ids.u32)));
      end
      if (m.pinning ~= 0)
        members = obj.push_member (members, 'pinning', B.add_ptr ( ...
                         B.add_array (ids.s32, m.pinning, ids.u32)));
      end
      if (m.map_extra ~= 0)
        members = obj.push_member (members, 'map_extra', B.add_ptr ( ...
                         B.add_array (ids.u64, m.map_extra, ids.u32)));
      end
      % Ring buffers have no key or value: the kernel requires key_size and
      % value_size to be zero, which libbpf derives from the absence of the
      % corresponding BTF members.
      if (~ m.is_ringbuf ())
        members = obj.push_member (members, 'key', B.add_ptr (m.key_type_id));
        members = obj.push_member (members, 'value', B.add_ptr (m.value_type_id));
      end

      sid = B.add_struct ('', members);
    end

    function members = push_member (obj, members, name, type)
      members(end+1) = struct ('name', name, 'type', type);
    end

    % ------------------------------------------------------------ assembler
    function img = assemble (obj)
      E = bpf.Elf ();
      B = bpf.BtfBuilder ();
      obj.m_btf = B;
      obj.m_base = [];

      % ---- BTF: base types and map definitions -------------------------
      ids = obj.base_types ();

      n = numel (obj.m_maps);
      map_sid = zeros (1, n);
      map_off = zeros (1, n);
      map_sz = zeros (1, n);
      maps_data = uint8 ([]);
      for k = 1:n
        map_sid(k) = obj.map_struct (obj.m_maps{k});
        sz = B.size_of (map_sid(k));
        off = ceil (numel (maps_data) / 8) * 8;
        if (off > numel (maps_data))
          maps_data = [maps_data, zeros(1, off - numel (maps_data), 'uint8')];
        end
        maps_data = [maps_data, zeros(1, sz, 'uint8')];
        map_off(k) = off;
        map_sz(k) = sz;
      end

      if (n > 0)
        B.add_datasec ('.maps', obj.datasec_vars (B, map_sid, map_off, map_sz));
      end
      btf_bytes = B.bytes ();

      % ---- sections -----------------------------------------------------
      prog_idx = zeros (1, numel (obj.m_progs));
      for k = 1:numel (obj.m_progs)
        pr = obj.m_progs{k};
        code = pr.asm.bytes ();          % N x 8, one instruction per row
        code = reshape (code.', 1, []);  % flatten in instruction order
        prog_idx(k) = E.add_section (pr.section, E.SHT_PROGBITS, ...
                                     bitor (E.SHF_ALLOC, E.SHF_EXECINSTR), ...
                                     8, code);
      end

      maps_idx = 0;
      if (n > 0)
        maps_idx = E.add_section ('.maps', E.SHT_PROGBITS, ...
                                  bitor (E.SHF_ALLOC, E.SHF_WRITE), ...
                                  8, maps_data);
      end

      lic = [uint8(obj.license), uint8(0)];
      lic_idx = E.add_section ('license', E.SHT_PROGBITS, ...
                               bitor (E.SHF_ALLOC, E.SHF_WRITE), 1, lic);

      btf_idx = E.add_section ('.BTF', E.SHT_PROGBITS, 0, 4, btf_bytes);

      % ---- symbols ------------------------------------------------------
      local = struct ('name', {}, 'value', {}, 'size', {}, 'info', {}, ...
                      'other', {}, 'shndx', {});
      for k = 1:numel (obj.m_progs)
        local(end+1) = struct ('name', '', 'value', 0, 'size', 0, ...
                               'info', bitor (bitshift (E.STB_LOCAL, 4), ...
                                              E.STT_SECTION), ...
                               'shndx', prog_idx(k), 'other', 0);
      end
      E.set_symbols (local);

      sym_of_map = zeros (1, n);
      sym_of_prog = zeros (1, numel (obj.m_progs));
      next = numel (local);
      for k = 1:n
        next = next + 1;
        sym_of_map(k) = next;
        E.add_symbol (obj.m_maps{k}.name, map_off(k), map_sz(k), ...
                      bitor (bitshift (E.STB_GLOBAL, 4), E.STT_OBJECT), ...
                      maps_idx);
      end
      for k = 1:numel (obj.m_progs)
        pr = obj.m_progs{k};
        next = next + 1;
        sym_of_prog(k) = next;
        E.add_symbol (pr.name, 0, pr.asm.count () * 8, ...
                      bitor (bitshift (E.STB_GLOBAL, 4), E.STT_FUNC), ...
                      prog_idx(k));
      end
      E.add_symbol ('LICENSE', 0, numel (lic), ...
                    bitor (bitshift (E.STB_GLOBAL, 4), E.STT_OBJECT), lic_idx);
      E.add_symbol ('.BTF', 0, numel (btf_bytes), ...
                    bitor (bitshift (E.STB_GLOBAL, 4), E.STT_OBJECT), btf_idx);

      % ---- relocations --------------------------------------------------
      for k = 1:numel (obj.m_progs)
        pr = obj.m_progs{k};
        rl = pr.asm.relocations ();
        entries = struct ('offset', {}, 'sym', {}, 'type', {});
        for j = 1:numel (rl)
          mi = obj.map_index (rl(j).sym);
          if (mi == 0)
            error ('bpf:Builder', 'program %s references unknown map %s', ...
                   pr.name, rl(j).sym);
          end
          entries(end+1) = struct ('offset', rl(j).slot * 8, ...
                                   'sym', sym_of_map(mi), ...
                                   'type', E.R_BPF_64_64);
        end
        E.add_relocs (prog_idx(k), entries);
      end

      img = E.bytes ();
    end

    function idx = map_index (obj, name)
      idx = 0;
      for k = 1:numel (obj.m_maps)
        if (strcmp (obj.m_maps{k}.name, name))
          idx = k;
          return;
        end
      end
    end

    function vars = datasec_vars (obj, B, sids, offs, szs)
      vars = struct ('type', {}, 'offset', {}, 'size', {});
      for k = 1:numel (sids)
        vid = B.add_var (obj.m_maps{k}.name, sids(k), B.VAR_GLOBAL_ALLOCATED);
        vars(end+1) = struct ('type', vid, 'offset', offs(k), 'size', szs(k));
      end
    end
  end
end
