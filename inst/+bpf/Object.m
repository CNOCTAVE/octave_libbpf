classdef Object < handle
%BPF.OBJECT  A libbpf BPF object (a collection of programs and maps).
%
%   OBJ = bpf.Object.from_file (PATH)
%   OBJ = bpf.Object.from_mem (BYTES [, NAME [, OPTS]])
%
%   Wraps 'struct bpf_object'.  The object owns every program and map that
%   it exposes as well as every link created through it, so clearing the
%   object detaches the links and closes the object.
%
%   Typical use:
%
%       obj = bpf.Object.from_mem (b.elf (), 'myprog');
%       obj.load ();
%       links = obj.attach_all ();
%
%       m = obj.find_map ('counts');
%       m.lookup (0)
%       clear obj            % detaches and closes
%
%   Metadata
%   --------
%     n = OBJ.name ()              object name
%     s = OBJ.program_names ()     cellstr of program names
%     s = OBJ.map_names ()         cellstr of map names
%     v = OBJ.kversion ()          kernel version recorded in the ELF
%     f = OBJ.btf_fd ()            file descriptor of the object BTF
%     b = OBJ.btf ()               bpf.BTF (borrowed, do not free)
%
%   Loading and attaching
%   ---------------------
%     OBJ.load ()
%     OBJ.prepare ()
%     L = OBJ.attach (NAME)        attach one program by name
%     L = OBJ.attach_all ()        attach every autoloadable program
%     OBJ.detach_all ()
%     OBJ.set_log (BYTES)          capture per program verifier logs
%     s = OBJ.get_log (NAME)
%
%   Lookup
%   ------
%     P = OBJ.find_program (NAME)
%     M = OBJ.find_map (NAME)
%     P = OBJ.programs ()          cell array of bpf.Program
%     M = OBJ.maps ()              cell array of bpf.Map
%
%   Pinning
%   -------
%     OBJ.pin (PATH)  OBJ.unpin (PATH)
%     OBJ.pin_maps (PATH)  OBJ.unpin_maps ([PATH])
%     OBJ.pin_programs (PATH)  OBJ.unpin_programs ([PATH])
%
%   See also bpf.Program, bpf.Map, bpf.Link, bpf.Builder.

  properties (SetAccess = protected)
    ptr = uint64 (0);
    loaded = false;
  end

  properties (Access = protected)
    m_name = '';
    m_links = {};
    m_progs = {};
    m_maps = {};
    m_logged = false;
  end

  methods

    function obj = Object (ptr, name)
      if (nargin < 1 || isempty (ptr))
        return;
      end
      if (nargin < 2 || isempty (name))
        name = '';
      end
      obj.ptr = uint64 (ptr);
      obj.m_name = name;
    end

    function delete (obj)
      obj.detach_all ();
      if (obj.ptr ~= 0)
        try
          libbpf_wrap ('object_close', obj.ptr);
        catch
          % never let cleanup raise
        end
        obj.ptr = uint64 (0);
      end
      obj.m_progs = {};
      obj.m_maps = {};
    end

    % ------------------------------------------------------------ metadata
    function s = name (obj)
      if (isempty (obj.m_name) && obj.ptr ~= 0)
        obj.m_name = libbpf_wrap ('object_name', obj.ptr);
      end
      s = obj.m_name;
    end

    function v = kversion (obj)
      v = libbpf_wrap ('object_kversion', obj.ptr);
    end

    function f = btf_fd (obj)
      f = libbpf_wrap ('object_btf_fd', obj.ptr);
    end

    function b = btf (obj)
      b = bpf.BTF (libbpf_wrap ('object_btf', obj.ptr), false);
    end

    function n = program_names (obj)
      n = cellstr (libbpf_wrap ('object_programs', obj.ptr));
    end

    function n = map_names (obj)
      n = cellstr (libbpf_wrap ('object_maps', obj.ptr));
    end

    % ------------------------------------------------------------- loading
    function load (obj)
      libbpf_wrap ('object_load', obj.ptr);
      obj.loaded = true;
    end

    function prepare (obj)
      libbpf_wrap ('object_prepare', obj.ptr);
    end

    function set_log (obj, bytes)
      if (nargin < 2 || isempty (bytes))
        bytes = 1024 * 1024;
      end
      libbpf_wrap ('object_set_log', obj.ptr, bytes);
      obj.m_logged = true;
    end

    function s = get_log (obj, name)
      p = obj.find_program (name);
      s = libbpf_wrap ('program_get_log', p.ptr);
    end

    % -------------------------------------------------------------- lookup
    function p = find_program (obj, name)
      for k = 1:numel (obj.m_progs)
        if (strcmp (obj.m_progs{k}.name, name))
          p = obj.m_progs{k};
          return;
        end
      end
      ptr = libbpf_wrap ('object_find_program', obj.ptr, name);
      if (ptr == 0)
        error ('bpf:Object', 'no program named "%s" in object "%s"', ...
               name, obj.name ());
      end
      p = bpf.Program (ptr, obj, name);
    end

    function m = find_map (obj, name)
      for k = 1:numel (obj.m_maps)
        if (strcmp (obj.m_maps{k}.name, name))
          m = obj.m_maps{k};
          return;
        end
      end
      ptr = libbpf_wrap ('object_find_map', obj.ptr, name);
      if (ptr == 0)
        error ('bpf:Object', 'no map named "%s" in object "%s"', ...
               name, obj.name ());
      end
      m = bpf.Map (ptr, name);
      obj.m_maps{end+1} = m;
    end

    function p = programs (obj)
      names = obj.program_names ();
      p = cell (1, numel (names));
      for k = 1:numel (names)
        p{k} = obj.find_program (names{k});
      end
    end

    function m = maps (obj)
      names = obj.map_names ();
      m = cell (1, numel (names));
      for k = 1:numel (names)
        m{k} = obj.find_map (names{k});
      end
    end

    % ------------------------------------------------------------ attaching
    function link = attach (obj, name)
      p = obj.find_program (name);
      link = p.attach ();
      obj.m_links{end+1} = link;
    end

    function links = attach_all (obj)
      names = obj.program_names ();
      links = {};
      for k = 1:numel (names)
        p = obj.find_program (names{k});
        if (~ p.autoattach ())
          continue;
        end
        l = p.attach ();
        obj.m_links{end+1} = l;
        links{end+1} = l;
      end
    end

    function detach_all (obj)
      for k = 1:numel (obj.m_links)
        try
          delete (obj.m_links{k});
        catch
        end
      end
      obj.m_links = {};
    end

    function l = links (obj)
      l = obj.m_links;
    end

    % ------------------------------------------------------------- pinning
    function pin (obj, path)
      libbpf_wrap ('object_pin', obj.ptr, path);
    end

    function unpin (obj, path)
      libbpf_wrap ('object_unpin', obj.ptr, path);
    end

    function pin_maps (obj, path)
      libbpf_wrap ('object_pin_maps', obj.ptr, path);
    end

    function unpin_maps (obj, path)
      if (nargin < 2)
        path = '';
      end
      libbpf_wrap ('object_unpin_maps', obj.ptr, path);
    end

    function pin_programs (obj, path)
      libbpf_wrap ('object_pin_programs', obj.ptr, path);
    end

    function unpin_programs (obj, path)
      if (nargin < 2)
        path = '';
      end
      libbpf_wrap ('object_unpin_programs', obj.ptr, path);
    end

    function disp (obj)
      if (obj.ptr == 0)
        fprintf ('  bpf.Object (closed)\n');
        return;
      end
      state = 'opened';
      if (obj.loaded)
        state = 'loaded';
      end
      fprintf ('  bpf.Object "%s" (%s)\n', obj.name (), state);
      pn = obj.program_names ();
      mn = obj.map_names ();
      fprintf ('    programs: %s\n', strjoin (pn, ', '));
      fprintf ('    maps:     %s\n', strjoin (mn, ', '));
    end
  end

  methods (Static)

    function obj = from_file (path, opts)
      if (nargin < 2)
        opts = struct ();
      end
      ptr = libbpf_wrap ('object_open_file', path, opts);
      obj = bpf.Object (ptr, '');
    end

    function obj = from_mem (data, name, opts)
      if (nargin < 2 || isempty (name))
        name = 'octave_bpf';
      end
      if (nargin < 3)
        opts = struct ();
      end
      ptr = libbpf_wrap ('object_open_mem', data, name, opts);
      obj = bpf.Object (ptr, name);
    end
  end
end
