classdef BtfBuilder < handle
%BPF.BTFBUILDER  BPF Type Format encoder.
%
%   B = bpf.BtfBuilder ()
%
%   Builds a BTF blob (the contents of the ELF '.BTF' section) from types
%   added one at a time.  Type identifiers are returned by every add_*
%   method; identifier 0 always denotes 'void'.
%
%   Types
%   -----
%     id = B.add_int (NAME, SIZE, ENCODING)
%     id = B.add_ptr (TYPE)
%     id = B.add_array (TYPE, NELEMS [, INDEX_TYPE])
%     id = B.add_struct (NAME, MEMBERS)
%     id = B.add_union (NAME, MEMBERS)
%     id = B.add_typedef (NAME, TYPE)
%     id = B.add_const (TYPE)      B.add_volatile (TYPE)   B.add_restrict (TYPE)
%     id = B.add_enum (NAME, NAMES, VALUES [, SIZE])
%     id = B.add_fwd (NAME [, IS_UNION])
%     id = B.add_func_proto (RET [, PARAMS])
%     id = B.add_func (NAME, PROTO [, LINKAGE])
%     id = B.add_var (NAME, TYPE [, LINKAGE])
%     id = B.add_datasec (NAME, VARS)
%     id = B.add_decl_tag (NAME, TYPE, COMPONENT_IDX)
%     id = B.add_type (KIND, NAME, SIZE_OR_TYPE, EXTRA, VLEN, KFLAG)
%
%   MEMBERS is a struct array with fields 'name' and 'type'; byte offsets
%   are assigned automatically using natural alignment.  VARS is a struct
%   array with fields 'type', 'offset' and 'size'.
%
%   Introspection
%   -------------
%     n = B.type_cnt ()      number of types (excluding void)
%     s = B.size_of (ID)     size in bytes of a type
%     s = B.name_of (ID)     type name
%     k = B.kind_of (ID)     BTF kind of a type
%     b = B.bytes ()         the encoded BTF blob (uint8 row vector)
%
%   See also bpf.Elf, bpf.Builder.

  properties (Access = private)
    m_kind = [];        % kind of every type
    m_name = [];        % name offset of every type
    m_sot = [];         % size or referenced type
    m_extra = {};       % extra bytes
    m_vlen = [];
    m_kflag = [];
    m_size = [];        % resolved size in bytes
    m_strmap = [];
    m_strbytes = uint8 (0);   % leading NUL for the empty string
  end

  properties (Constant)
    KIND_UNKN = 0;
    KIND_INT = 1;
    KIND_PTR = 2;
    KIND_ARRAY = 3;
    KIND_STRUCT = 4;
    KIND_UNION = 5;
    KIND_ENUM = 6;
    KIND_FWD = 7;
    KIND_TYPEDEF = 8;
    KIND_VOLATILE = 9;
    KIND_CONST = 10;
    KIND_RESTRICT = 11;
    KIND_FUNC = 12;
    KIND_FUNC_PROTO = 13;
    KIND_VAR = 14;
    KIND_DATASEC = 15;
    KIND_FLOAT = 16;
    KIND_DECL_TAG = 17;
    KIND_TYPE_TAG = 18;
    KIND_ENUM64 = 19;

    ENC_NONE = 0;
    ENC_SIGNED = 1;
    ENC_CHAR = 2;
    ENC_BOOL = 4;

    VAR_STATIC = 0;
    VAR_GLOBAL_ALLOCATED = 1;
    VAR_GLOBAL_EXTERN = 2;
  end

  methods

    function obj = BtfBuilder ()
      obj.m_strmap = containers.Map ('KeyType', 'char', 'ValueType', 'double');
      obj.m_strmap ('') = 0;
    end

    % ------------------------------------------------------------- strings
    function off = add_str (obj, s)
      if (isempty (s))
        off = 0;
        return;
      end
      if (isKey (obj.m_strmap, s))
        off = obj.m_strmap (s);
        return;
      end
      off = numel (obj.m_strbytes);
      buf = obj.m_strbytes;
      buf = [buf, uint8(s), uint8(0)];
      obj.m_strbytes = buf;
      mp = obj.m_strmap;
      mp(s) = off;
      obj.m_strmap = mp;
    end

    % --------------------------------------------------------------- types
    function id = add_type (obj, kind, name, sot, extra, vlen, kflag)
      if (nargin < 5 || isempty (extra))
        extra = uint8 ([]);
      end
      if (nargin < 6 || isempty (vlen))
        vlen = 0;
      end
      if (nargin < 7 || isempty (kflag))
        kflag = 0;
      end
      obj.m_kind(end+1) = kind;
      obj.m_name(end+1) = obj.add_str (name);
      obj.m_sot(end+1) = sot;
      obj.m_extra{end+1} = extra(:)';
      obj.m_vlen(end+1) = vlen;
      obj.m_kflag(end+1) = kflag;
      obj.m_size(end+1) = obj.resolve_size (kind, sot, vlen);
      id = numel (obj.m_kind);
    end

    function id = add_int (obj, name, sz, encoding)
      if (nargin < 4 || isempty (encoding))
        encoding = 0;
      end
      if (nargin < 3 || isempty (sz))
        sz = 4;
      end
      % BTF_INT encoding word: bits 0-7 bit width, 16-23 bit offset,
      % 24-27 encoding (none/signed/char/bool)
      enc = bitor (mod (sz * 8, 256), bitshift (mod (encoding, 16), 24));
      id = obj.add_type (obj.KIND_INT, name, sz, uint32le (enc), 0, 0);
    end

    function id = add_ptr (obj, type)
      id = obj.add_type (obj.KIND_PTR, '', type, uint8 ([]), 0, 0);
    end

    function id = add_array (obj, type, nelems, index_type)
      % B.add_array (ELEMENT_TYPE, NELEMS [, INDEX_TYPE])
      if (nargin < 4 || isempty (index_type))
        index_type = 1;   % first INT type added; a sane default index type
      end
      extra = [uint32le(type), uint32le(index_type), uint32le(nelems)];
      % For BTF_KIND_ARRAY the size/type union member is unused and the
      % kernel verifier insists that it is zero.
      id = obj.add_type (obj.KIND_ARRAY, '', 0, extra, 0, 0);
    end

    function id = add_struct (obj, name, members)
      [extra, sz, vlen] = obj.layout (members);
      id = obj.add_type (obj.KIND_STRUCT, name, sz, extra, vlen, 0);
      obj.m_size(id) = sz;
    end

    function id = add_union (obj, name, members)
      extra = uint8 ([]);
      sz = 0;
      for k = 1:numel (members)
        extra = [extra, uint32le(obj.add_str (members(k).name)), ...
                 uint32le(members(k).type), uint32le(0)];
        sz = max (sz, obj.size_of (members(k).type));
      end
      id = obj.add_type (obj.KIND_UNION, name, sz, extra, numel (members), 0);
      obj.m_size(id) = sz;
    end

    function id = add_typedef (obj, name, type)
      id = obj.add_type (obj.KIND_TYPEDEF, name, type, uint8 ([]), 0, 0);
    end

    function id = add_const (obj, type)
      id = obj.add_type (obj.KIND_CONST, '', type, uint8 ([]), 0, 0);
    end

    function id = add_volatile (obj, type)
      id = obj.add_type (obj.KIND_VOLATILE, '', type, uint8 ([]), 0, 0);
    end

    function id = add_restrict (obj, type)
      id = obj.add_type (obj.KIND_RESTRICT, '', type, uint8 ([]), 0, 0);
    end

    function id = add_enum (obj, name, names, values, sz)
      if (nargin < 5 || isempty (sz))
        sz = 4;
      end
      extra = uint8 ([]);
      for k = 1:numel (names)
        extra = [extra, uint32le(obj.add_str (names{k})), int32le(values(k))];
      end
      id = obj.add_type (obj.KIND_ENUM, name, sz, extra, numel (names), 0);
      obj.m_size(id) = sz;
    end

    function id = add_fwd (obj, name, is_union)
      if (nargin < 3 || isempty (is_union))
        is_union = false;
      end
      id = obj.add_type (obj.KIND_FWD, name, double (is_union), ...
                         uint8 ([]), 0, 0);
    end

    function id = add_func_proto (obj, ret, params)
      if (nargin < 3 || isempty (params))
        params = struct ('name', {}, 'type', {});
      end
      extra = uint8 ([]);
      for k = 1:numel (params)
        extra = [extra, uint32le(obj.add_str (params(k).name)), ...
                 uint32le(params(k).type)];
      end
      id = obj.add_type (obj.KIND_FUNC_PROTO, '', ret, extra, numel (params), 0);
    end

    function id = add_func (obj, name, proto, linkage)
      if (nargin < 4 || isempty (linkage))
        linkage = 1;   % BTF_FUNC_GLOBAL
      end
      id = obj.add_type (obj.KIND_FUNC, name, proto, uint32le(linkage), 0, 0);
    end

    function id = add_var (obj, name, type, linkage)
      if (nargin < 4 || isempty (linkage))
        linkage = obj.VAR_GLOBAL_ALLOCATED;
      end
      id = obj.add_type (obj.KIND_VAR, name, type, uint32le(linkage), 0, 0);
    end

    function id = add_datasec (obj, name, vars)
      extra = uint8 ([]);
      sz = 0;
      for k = 1:numel (vars)
        extra = [extra, uint32le(vars(k).type), uint32le(vars(k).offset), ...
                 uint32le(vars(k).size)];
        sz = max (sz, vars(k).offset + vars(k).size);
      end
      id = obj.add_type (obj.KIND_DATASEC, name, sz, extra, numel (vars), 0);
      obj.m_size(id) = sz;
    end

    function id = add_decl_tag (obj, name, type, component_idx)
      id = obj.add_type (obj.KIND_DECL_TAG, name, type, ...
                         int32le (component_idx), 0, 0);
    end

    % ------------------------------------------------------- introspection
    function n = type_cnt (obj)
      n = numel (obj.m_kind);
    end

    function s = size_of (obj, id)
      if (id <= 0 || id > numel (obj.m_size))
        s = 0;
      else
        s = obj.m_size(id);
      end
    end

    function nm = name_of (obj, id)
      if (id <= 0 || id > numel (obj.m_name))
        nm = '';
        return;
      end
      nm = obj.str_at (obj.m_name(id));
    end

    function k = kind_of (obj, id)
      k = obj.m_kind(id);
    end

    % -------------------------------------------------------------- output
    function b = bytes (obj)
      types = uint8 ([]);
      for k = 1:numel (obj.m_kind)
        info = bitor (bitor (bitshift (obj.m_kind(k), 24), obj.m_vlen(k)), ...
                      bitshift (obj.m_kflag(k), 31));
        types = [types, uint32le(obj.m_name(k)), uint32le(info), ...
                 uint32le(obj.m_sot(k)), obj.m_extra{k}];
      end
      strs = obj.m_strbytes;

      hdr = [uint16le(hex2dec('eb9f')), uint8(1), uint8(0), uint32le(24), ...
             uint32le(0), uint32le(numel(types)), ...
             uint32le(numel(types)), uint32le(numel(strs))];
      b = [hdr, types, strs];
    end
  end

  methods (Access = private)

    function s = str_at (obj, off)
      keys = obj.m_strmap.keys ();
      vals = obj.m_strmap.values ();
      s = '';
      for k = 1:numel (keys)
        if (vals{k} == off)
          s = keys{k};
          return;
        end
      end
      raw = obj.m_strbytes;
      if (off < numel (raw))
        e = off + 1;
        while (e <= numel (raw) && raw(e) ~= 0)
          e = e + 1;
        end
        s = char (raw(off+1:e-1));
      end
    end

    function [extra, sz, vlen] = layout (obj, members)
      extra = uint8 ([]);
      off = 0;
      for k = 1:numel (members)
        tsz = obj.size_of (members(k).type);
        if (tsz <= 0)
          tsz = 8;   % pointers and forward references
        end
        al = min (max (tsz, 1), 8);
        off = ceil (off / al) * al;
        extra = [extra, uint32le(obj.add_str (members(k).name)), ...
                 uint32le(members(k).type), uint32le(off * 8)];
        off = off + tsz;
      end
      al = 1;
      for k = 1:numel (members)
        tsz = obj.size_of (members(k).type);
        if (tsz <= 0)
          tsz = 8;
        end
        al = max (al, min (max (tsz, 1), 8));
      end
      sz = ceil (off / al) * al;
      vlen = numel (members);
    end

    function s = resolve_size (obj, kind, sot, vlen)
      if (kind == obj.KIND_ARRAY)
        extra = uint32fromle (obj.m_extra{end});
        if (numel (extra) >= 3 && extra(1) >= 1 && extra(1) <= numel (obj.m_size))
          s = extra(3) * obj.m_size(extra(1));
          if (s == 0)
            s = extra(3) * 8;
          end
        else
          s = 0;
        end
        return;
      end
      switch kind
        case {obj.KIND_INT, obj.KIND_STRUCT, obj.KIND_UNION, obj.KIND_ENUM, ...
              obj.KIND_ENUM64, obj.KIND_FLOAT}
          s = sot;
        case obj.KIND_PTR
          s = 8;
        case {obj.KIND_TYPEDEF, obj.KIND_CONST, obj.KIND_VOLATILE, ...
              obj.KIND_RESTRICT, obj.KIND_TYPE_TAG}
          if (sot >= 1 && sot <= numel (obj.m_size))
            s = obj.m_size(sot);
          else
            s = 0;
          end
        otherwise
          s = 0;
      end
    end
  end
end

% ---------------------------------------------------------------------------

function b = uint16le (v)
  b = lebytes (v, 2);
end

function b = uint32le (v)
  b = lebytes (v, 4);
end

function b = int32le (v)
  b = lebytes (v, 4);
end

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

function v = uint32fromle (b)
  b = double (b(:)');
  n = floor (numel (b) / 4);
  v = zeros (1, n);
  for k = 1:n
    seg = b((k-1)*4 + (1:4));
    v(k) = seg(1) + 256 * seg(2) + 65536 * seg(3) + 16777216 * seg(4);
  end
end
