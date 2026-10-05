classdef Map < handle
%BPF.MAP  An eBPF map belonging to a bpf.Object.
%
%   Maps are obtained from a bpf.Object or created with bpf.Map.create.
%   Maps owned by an object must not be freed by the user.
%
%   Metadata
%   --------
%     f = M.fd ()                file descriptor
%     s = M.name ()              map name
%     t = M.type ()              struct with 'value' and 'name'
%     k = M.key_size ()          key size in bytes
%     v = M.value_size ()        value size in bytes
%     n = M.max_entries ()       maximum number of entries
%     i = M.info ()              struct from BPF_OBJ_GET_INFO_BY_FD
%     b = M.is_ringbuf ()        true for BPF_MAP_TYPE_RINGBUF/USER_RINGBUF
%
%   Element access
%   --------------
%   Keys and values may be given either as integer scalars (converted
%   according to the map's key/value size) or as uint8 byte vectors.
%
%     v = M.lookup (KEY)                 value (numeric for 1/2/4/8 bytes)
%     b = M.lookup (KEY, 'raw')          value as uint8 bytes
%     M.update (KEY, VALUE [, FLAGS])
%     M.remove (KEY)
%     v = M.lookup_and_delete (KEY)
%     k = M.next_key ([KEY])             [] when the iteration is finished
%     ks = M.keys ()                     all keys (cell array)
%     M.freeze ()
%
%   Pinning
%   -------
%     M.set_pin_path (PATH)   M.pin ([PATH])   M.unpin ([PATH])
%     s = M.pin_path ()       b = M.is_pinned ()
%
%   Standalone maps (not part of an object)
%   ---------------------------------------
%     M = bpf.Map.create (TYPE, KEY_SIZE, VALUE_SIZE, MAX_ENTRIES
%                         [, NAME [, OPTS]])
%     M = bpf.Map.from_fd (FD)
%
%   See also bpf.Object, bpf.RingBuf, bpf.PerfBuf.

  properties
    ptr = uint64 (0);     % struct bpf_map * (0 for standalone maps)
    fd_ = -1;             % file descriptor for standalone maps
    name = '';
    owned = false;        % true when the wrapper created the map itself
  end

  methods

    function m = Map (ptr, name, owned)
      if (nargin < 1 || isempty (ptr))
        return;
      end
      m.ptr = uint64 (ptr);
      if (nargin > 1 && ~ isempty (name))
        m.name = name;
      else
        m.name = libbpf_wrap ('map_name', m.ptr);
      end
      if (nargin > 2)
        m.owned = logical (owned);
      end
    end

    function delete (obj)
      if (obj.owned && obj.fd_ >= 0)
        try
          libbpf_wrap ('close_fd', obj.fd_);
        catch
        end
        obj.fd_ = -1;
      end
    end

    % ------------------------------------------------------------ metadata
    function f = fd (obj)
      if (obj.ptr ~= 0)
        f = libbpf_wrap ('map_fd', obj.ptr);
      else
        f = obj.fd_;
      end
    end

    function t = type (obj)
      if (obj.ptr ~= 0)
        t = libbpf_wrap ('map_type', obj.ptr);
      else
        v = obj.info ().type;
        t = struct ('value', v, ...
                    'name', libbpf_wrap ('type_str', 'map_type', v));
      end
    end

    function k = key_size (obj)
      if (obj.ptr ~= 0)
        k = libbpf_wrap ('map_key_size', obj.ptr);
      else
        k = obj.info ().key_size;
      end
    end

    function v = value_size (obj)
      if (obj.ptr ~= 0)
        v = libbpf_wrap ('map_value_size', obj.ptr);
      else
        v = obj.info ().value_size;
      end
    end

    function n = max_entries (obj)
      if (obj.ptr ~= 0)
        n = libbpf_wrap ('map_max_entries', obj.ptr);
      else
        n = obj.info ().max_entries;
      end
    end

    function tf = is_ringbuf (obj)
      t = obj.type ();
      tf = any (t.value == [27, 31]);
    end

    function i = info (obj)
      i = libbpf_wrap ('map_get_info', obj.fd ());
    end

    % ------------------------------------------------------------- pinning
    function set_pin_path (obj, path)
      libbpf_wrap ('map_set_pin_path', obj.ptr, path);
    end

    function p = pin_path (obj)
      p = libbpf_wrap ('map_pin_path', obj.ptr);
    end

    function tf = is_pinned (obj)
      tf = libbpf_wrap ('map_is_pinned', obj.ptr);
    end

    function pin (obj, path)
      if (nargin < 2)
        path = '';
      end
      libbpf_wrap ('map_pin', obj.ptr, path);
    end

    function unpin (obj, path)
      if (nargin < 2)
        path = '';
      end
      libbpf_wrap ('map_unpin', obj.ptr, path);
    end

    % -------------------------------------------------------- element access
    function out = lookup (obj, key, mode)
      if (nargin < 3)
        mode = 'auto';
      end
      b = obj.raw_lookup (key);
      if (strcmp (mode, 'raw'))
        out = b;
      else
        out = bpf.bytes2num (b);
      end
    end

    function b = lookup_raw (obj, key)
      b = obj.raw_lookup (key);
    end

    function update (obj, key, value, flags)
      if (nargin < 4)
        flags = 0;
      end
      kb = obj.pack (key, obj.key_size ());
      vb = obj.pack (value, obj.value_size ());
      if (obj.ptr ~= 0)
        libbpf_wrap ('map_update', obj.ptr, kb, vb, flags);
      else
        libbpf_wrap ('map_update_fd', obj.fd_, kb, vb, flags);
      end
    end

    function remove (obj, key)
      kb = obj.pack (key, obj.key_size ());
      if (obj.ptr ~= 0)
        libbpf_wrap ('map_delete', obj.ptr, kb);
      else
        libbpf_wrap ('map_delete_fd', obj.fd_, kb);
      end
    end

    function out = lookup_and_delete (obj, key, mode)
      if (nargin < 3)
        mode = 'auto';
      end
      b = libbpf_wrap ('map_lookup_and_delete', obj.ptr, ...
                       obj.pack (key, obj.key_size ()));
      if (strcmp (mode, 'raw'))
        out = b;
      else
        out = bpf.bytes2num (b);
      end
    end

    function k = next_key (obj, key)
      kb = [];
      if (nargin > 1 && ~ isempty (key))
        kb = obj.pack (key, obj.key_size ());
      end
      if (obj.ptr ~= 0)
        if (isempty (kb))
          k = libbpf_wrap ('map_get_next_key', obj.ptr);
        else
          k = libbpf_wrap ('map_get_next_key', obj.ptr, kb);
        end
      else
        if (isempty (kb))
          k = libbpf_wrap ('map_next_key_fd', obj.fd_, uint8 ([]), obj.key_size ());
        else
          k = libbpf_wrap ('map_next_key_fd', obj.fd_, kb, obj.key_size ());
        end
      end
      if (isempty (k))
        k = [];
      else
        k = bpf.bytes2num (k);
      end
    end

    function ks = keys (obj)
      ks = {};
      k = obj.next_key ();
      while (~ isempty (k))
        ks{end+1} = k;
        k = obj.next_key (k);
      end
    end

    function freeze (obj)
      libbpf_wrap ('map_freeze', obj.fd ());
    end

    function disp (obj)
      t = obj.type ();
      fprintf ('  bpf.Map "%s" type=%s key=%d value=%d max_entries=%d fd=%d\n', ...
               obj.name, t.name, obj.key_size (), obj.value_size (), ...
               obj.max_entries (), obj.fd ());
    end
  end

  methods (Access = protected)

    function b = raw_lookup (obj, key)
      kb = obj.pack (key, obj.key_size ());
      if (obj.ptr ~= 0)
        b = libbpf_wrap ('map_lookup', obj.ptr, kb);
      else
        b = libbpf_wrap ('map_lookup_fd', obj.fd_, kb, obj.value_size ());
      end
    end

    function b = pack (obj, v, n)
      if (isa (v, 'uint8') && isrow (v))
        b = v;
      else
        b = bpf.num2bytes (v, n);
      end
    end
  end

  methods (Static)

    function m = create (type, key_size, value_size, max_entries, name, opts)
      if (nargin < 5 || isempty (name))
        name = '';
      end
      if (nargin < 6)
        opts = struct ();
      end
      mtype = bpf.map_type (type);
      f = libbpf_wrap ('map_create', mtype, name, key_size, value_size, ...
                       max_entries, opts);
      m = bpf.Map ();
      m.fd_ = f;
      m.owned = true;
      m.name = name;
      m.ptr = uint64 (0);
    end

    function m = from_fd (fd, owned)
      if (nargin < 2)
        owned = false;
      end
      m = bpf.Map ();
      m.fd_ = fd;
      m.owned = logical (owned);
      m.ptr = uint64 (0);
    end
  end
end
