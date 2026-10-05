classdef PerfBuf < handle
%BPF.PERFBUF  Consumer for a BPF perf event array map.
%
%   PB = bpf.PerfBuf (MAP [, PAGE_CNT])
%
%   Samples are returned as a cell array of structs with fields 'cpu' and
%   'data' (uint8 row vector).
%
%     [s, lost] = PB.poll (TIMEOUT_MS [, MAX_SAMPLES])
%     [s, lost] = PB.consume ()
%     n = PB.buffer_cnt ()    f = PB.epoll_fd ()
%
%   See also bpf.Map, bpf.RingBuf.

  properties
    ptr = uint64 (0);
    ctx = uint64 (0);
  end

  methods

    function pb = PerfBuf (map, page_cnt)
      if (nargin < 1 || isempty (map))
        return;
      end
      if (nargin < 2 || isempty (page_cnt))
        page_cnt = 0;
      end
      if (isa (map, 'bpf.Map'))
        f = map.fd ();
      else
        f = map;
      end
      [p, c] = libbpf_wrap ('perfbuf_new', f, page_cnt);
      pb.ptr = uint64 (p);
      pb.ctx = uint64 (c);
    end

    function delete (obj)
      if (obj.ptr ~= 0)
        try
          libbpf_wrap ('perfbuf_free', obj.ptr, obj.ctx);
        catch
        end
      end
      obj.ptr = uint64 (0);
      obj.ctx = uint64 (0);
    end

    function [samples, lost] = poll (obj, timeout_ms, max_samples)
      if (nargin < 2 || isempty (timeout_ms))
        timeout_ms = 100;
      end
      if (nargin < 3)
        max_samples = 0;
      end
      [samples, lost] = libbpf_wrap ('perfbuf_poll', obj.ptr, obj.ctx, ...
                                     timeout_ms, max_samples);
    end

    function [samples, lost] = consume (obj)
      [samples, lost] = libbpf_wrap ('perfbuf_consume', obj.ptr, obj.ctx);
    end

    function n = buffer_cnt (obj)
      n = libbpf_wrap ('perfbuf_buffer_cnt', obj.ptr);
    end

    function f = epoll_fd (obj)
      f = libbpf_wrap ('perfbuf_epoll_fd', obj.ptr);
    end

    function disp (obj)
      fprintf ('  bpf.PerfBuf buffers=%d epoll_fd=%d\n', ...
               obj.buffer_cnt (), obj.epoll_fd ());
    end
  end
end
