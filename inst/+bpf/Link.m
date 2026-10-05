classdef Link < handle
%BPF.LINK  A bpf_link: the result of attaching an eBPF program.
%
%   L = bpf.Link (PTR)         wrap an existing 'struct bpf_link *'
%   L = bpf.Link.open (PATH)   open a pinned link
%
%   Clearing the wrapper destroys the link, which detaches the program.
%   Use L.disconnect () first if the link must outlive the wrapper.
%
%     f = L.fd ()                link file descriptor
%     L.destroy ()               detach and free
%     L.detach ()                detach but keep the link object alive
%     L.disconnect ()            stop the wrapper from destroying the link
%     L.pin (PATH)  L.unpin ()   s = L.pin_path ()
%     L.update_program (P)       L.update_map (M)
%
%   See also bpf.Program, bpf.Object.

  properties
    ptr = uint64 (0);
    detached = false;
  end

  methods

    function l = Link (ptr)
      if (nargin < 1 || isempty (ptr) || ptr == 0)
        return;
      end
      l.ptr = uint64 (ptr);
    end

    function delete (obj)
      if (obj.ptr ~= 0 && ~ obj.detached)
        try
          libbpf_wrap ('link_destroy', obj.ptr);
        catch
        end
      end
      obj.ptr = uint64 (0);
    end

    function f = fd (obj)
      f = libbpf_wrap ('link_fd', obj.ptr);
    end

    function destroy (obj)
      if (obj.ptr ~= 0)
        libbpf_wrap ('link_destroy', obj.ptr);
        obj.ptr = uint64 (0);
      end
    end

    function detach (obj)
      libbpf_wrap ('link_detach', obj.ptr);
      obj.detached = true;
    end

    function disconnect (obj)
      libbpf_wrap ('link_disconnect', obj.ptr);
      obj.detached = true;
    end

    function pin (obj, path)
      libbpf_wrap ('link_pin', obj.ptr, path);
    end

    function unpin (obj)
      libbpf_wrap ('link_unpin', obj.ptr);
    end

    function p = pin_path (obj)
      p = libbpf_wrap ('link_pin_path', obj.ptr);
    end

    function update_program (obj, prog)
      libbpf_wrap ('link_update_program', obj.ptr, prog.ptr);
    end

    function update_map (obj, map)
      libbpf_wrap ('link_update_map', obj.ptr, map.ptr);
    end

    function disp (obj)
      fprintf ('  bpf.Link fd=%d\n', obj.fd ());
    end
  end

  methods (Static)
    function l = open (path)
      l = bpf.Link (libbpf_wrap ('link_open', path));
    end
  end
end
