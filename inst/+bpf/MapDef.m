classdef MapDef < handle
%BPF.MAPDEF  Description of an eBPF map.
%
%   Map definitions are normally created through bpf.Builder.map:
%
%       b = bpf.Builder ('GPL');
%       counts = b.map ('counts', 'array', 'u32', 'u64', 8);
%
%   Properties
%   ----------
%     name         map name as seen from Octave and libbpf
%     type         numeric BPF_MAP_TYPE_* value
%     type_name    canonical type name
%     key          key type specification (see bpf.Builder.map)
%     value        value type specification
%     max_entries  number of entries (bytes for ring buffers)
%     map_flags    BPF_F_* creation flags
%     pinning      0 = none, 1 = pin by name
%     numa_node    NUMA node for the map
%     map_extra    extra flags passed to the kernel
%     key_size     explicit key size override (bytes, [] = derive)
%     value_size   explicit value size override (bytes, [] = derive)
%
%   See also bpf.Builder.

  properties
    name = '';
    type = 0;
    type_name = '';
    key = 'u32';
    value = 'u64';
    max_entries = 1;
    map_flags = 0;
    pinning = 0;
    numa_node = 0;
    map_extra = 0;
    key_size = [];
    value_size = [];
    value_type_id = 0;   % resolved BTF type id (filled in by the builder)
    key_type_id = 0;
  end

  methods
    function obj = MapDef (name, type, key, value, maxentries)
      if (nargin > 0)
        obj.name = name;
      end
      if (nargin > 1)
        [obj.type, obj.type_name] = bpf.map_type (type);
      end
      if (nargin > 2)
        obj.key = key;
      end
      if (nargin > 3)
        obj.value = value;
      end
      if (nargin > 4)
        obj.max_entries = maxentries;
      end
    end

    function s = is_ringbuf (obj)
      s = any (obj.type == [27, 31]);   % BPF_MAP_TYPE_RINGBUF / USER_RINGBUF
    end

    function s = is_percpu (obj)
      s = any (obj.type == [5, 6, 10, 21]);   % PERCPU_HASH/ARRAY, LRU_PERCPU_HASH
    end

    function disp (obj)
      fprintf ('  bpf.MapDef %s: %s key=%s value=%s max_entries=%d\n', ...
               obj.name, obj.type_name, tostr (obj.key), tostr (obj.value), ...
               obj.max_entries);
    end
  end
end

function s = tostr (v)
  if (ischar (v))
    s = v;
  elseif (isnumeric (v))
    s = sprintf ('opaque(%d)', v);
  else
    s = '<btf>';
  end
end
