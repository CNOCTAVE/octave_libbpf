classdef RingBuf < handle
%BPF.RINGBUF  Consumer for a BPF ring buffer map.
%
%   RB = bpf.RingBuf (MAP)     MAP is a bpf.Map of type 'ringbuf'
%
%   Samples are collected by the C layer while polling and returned to
%   Octave as a cell array of uint8 row vectors, so no Octave callback is
%   invoked from inside libbpf.
%
%     [s, lost] = RB.poll (TIMEOUT_MS [, MAX_SAMPLES])
%     [s, lost] = RB.consume ([MAX_SAMPLES])
%     RB.add (MAP)               add a second ring buffer
%     f = RB.epoll_fd ()
%
%   TIMEOUT_MS may be 0 for a non blocking poll; a negative value blocks.
%
%   See also bpf.Map, bpf.PerfBuf.

  properties
    ptr = uint64 (0);
    ctx = uint64 (0);
  end

  methods

    function rb = RingBuf (map)
      if (nargin < 1 || isempty (map))
        return;
      end
      if (isa (map, 'bpf.Map'))
        f = map.fd ();
      else
        f = map;
      end
      [p, c] = libbpf_wrap ('ringbuf_new', f);
      rb.ptr = uint64 (p);
      rb.ctx = uint64 (c);
    end

    function delete (obj)
      if (obj.ptr ~= 0)
        try
          libbpf_wrap ('ringbuf_free', obj.ptr, obj.ctx);
        catch
        end
      end
      obj.ptr = uint64 (0);
      obj.ctx = uint64 (0);
    end

    function add (obj, map)
      libbpf_wrap ('ringbuf_add', obj.ptr, map.fd (), obj.ctx);
    end

    function [samples, lost] = poll (obj, timeout_ms, max_samples)
      if (nargin < 2 || isempty (timeout_ms))
        timeout_ms = 100;
      end
      if (nargin < 3)
        max_samples = 0;
      end
      [samples, lost] = libbpf_wrap ('ringbuf_poll', obj.ptr, obj.ctx, ...
                                     timeout_ms, max_samples);
    end

    function [samples, lost] = consume (obj, max_samples)
      if (nargin < 2)
        max_samples = 0;
      end
      [samples, lost] = libbpf_wrap ('ringbuf_consume', obj.ptr, obj.ctx, ...
                                     max_samples);
    end

    function f = epoll_fd (obj)
      f = libbpf_wrap ('ringbuf_epoll_fd', obj.ptr);
    end

    function disp (obj)
      fprintf ('  bpf.RingBuf epoll_fd=%d\n', obj.epoll_fd ());
    end
  end
end
