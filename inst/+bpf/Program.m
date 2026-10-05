classdef Program < handle
%BPF.PROGRAM  A single eBPF program inside a bpf.Object.
%
%   Programs are obtained from a bpf.Object; they are owned by the object
%   and must not be freed by the user.
%
%   Metadata
%   --------
%     f = P.fd ()                  program file descriptor (-1 if not loaded)
%     s = P.name ()                program name
%     s = P.section ()             ELF section name (e.g. 'kprobe/do_sys_open')
%     t = P.type ()                struct with 'value' and 'name'
%     e = P.expected_attach_type ()
%     n = P.insn_cnt ()            number of instructions
%     b = P.insns ()               Nx8 uint8 instruction stream
%     a = P.autoload ()            P.set_autoload (BOOL)
%     a = P.autoattach ()          P.set_autoattach (BOOL)
%
%   Attaching
%   ---------
%     L = P.attach ()                        auto attach using the section name
%     L = P.attach_kprobe (FUNC [, OPTS])    OPTS.retprobe
%     L = P.attach_kprobe_multi ([PATTERN], OPTS)   OPTS.syms, OPTS.retprobe
%     L = P.attach_uprobe (PID, PATH [, OFF [, OPTS]])
%     L = P.attach_uprobe_multi (PID, PATH [, PATTERN [, OPTS]])
%     L = P.attach_tracepoint (CATEGORY, NAME [, OPTS])
%     L = P.attach_raw_tracepoint (NAME)
%     L = P.attach_trace ()                  fentry / fexit / fmod_ret
%     L = P.attach_lsm ()
%     L = P.attach_cgroup (CGROUP_FD)
%     L = P.attach_netns (NETNS_FD)
%     L = P.attach_xdp (IFINDEX)
%     L = P.attach_tcx (IFINDEX [, OPTS])
%     L = P.attach_netkit (IFINDEX [, OPTS])
%     L = P.attach_sockmap (MAP_FD)
%     L = P.attach_freplace (TARGET_FD [, FUNC])
%     L = P.attach_netfilter (OPTS)
%     L = P.attach_iter ()
%     L = P.attach_usdt (PID, PATH, PROVIDER, NAME [, OPTS])
%     L = P.attach_perf_event (PERF_FD [, OPTS])
%     L = P.attach_ksyscall (SYSCALL [, OPTS])
%
%   Running and debugging
%   ---------------------
%     r = P.test_run ([DATA [, REPEAT [, OPTS]]])
%     P.set_log_level (LEVEL)   P.set_log_buf ([BYTES])   s = P.get_log ()
%     P.set_attach_target (BTF_ID [, FUNC])
%     P.pin (PATH)   P.unpin (PATH)
%
%   See also bpf.Object, bpf.Link.

  properties (SetAccess = protected)
    ptr = uint64 (0);
    name = '';
    obj = [];
  end

  methods

    function p = Program (ptr, obj, name)
      if (nargin < 1 || isempty (ptr))
        return;
      end
      p.ptr = uint64 (ptr);
      if (nargin > 1)
        p.obj = obj;
      end
      if (nargin > 2 && ~ isempty (name))
        p.name = name;
      else
        p.name = libbpf_wrap ('program_name', p.ptr);
      end
    end

    % ------------------------------------------------------------ metadata
    function f = fd (obj)
      f = libbpf_wrap ('program_fd', obj.ptr);
    end

    function s = section (obj)
      s = libbpf_wrap ('program_section_name', obj.ptr);
    end

    function t = type (obj)
      t = libbpf_wrap ('program_type', obj.ptr);
    end

    function t = expected_attach_type (obj)
      t = libbpf_wrap ('program_expected_attach_type', obj.ptr);
    end

    function n = insn_cnt (obj)
      n = libbpf_wrap ('program_insn_cnt', obj.ptr);
    end

    function b = insns (obj)
      b = libbpf_wrap ('program_insns', obj.ptr);
    end

    function a = autoload (obj)
      a = libbpf_wrap ('program_autoload', obj.ptr);
    end

    function set_autoload (obj, tf)
      libbpf_wrap ('program_set_autoload', obj.ptr, logical (tf));
    end

    function a = autoattach (obj)
      a = libbpf_wrap ('program_autoattach', obj.ptr);
    end

    function set_autoattach (obj, tf)
      libbpf_wrap ('program_set_autoattach', obj.ptr, logical (tf));
    end

    % ------------------------------------------------------------- logging
    function set_log_level (obj, level)
      libbpf_wrap ('program_set_log_level', obj.ptr, level);
    end

    function set_log_buf (obj, bytes)
      if (nargin < 2 || isempty (bytes))
        bytes = 1024 * 1024;
      end
      libbpf_wrap ('program_set_log_buf', obj.ptr, bytes);
    end

    function s = get_log (obj)
      s = libbpf_wrap ('program_get_log', obj.ptr);
    end

    function set_attach_target (obj, btf_id, func)
      if (nargin < 3)
        func = '';
      end
      libbpf_wrap ('program_set_attach_target', obj.ptr, btf_id, func);
    end

    function pin (obj, path)
      libbpf_wrap ('program_pin', obj.ptr, path);
    end

    function unpin (obj, path)
      libbpf_wrap ('program_unpin', obj.ptr, path);
    end

    % ----------------------------------------------------------- attaching
    function l = attach (obj)
      l = bpf.Link (libbpf_wrap ('attach_auto', obj.ptr));
    end

    function l = attach_kprobe (obj, func, opts)
      if (nargin < 3)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_kprobe', obj.ptr, func, opts));
    end

    function l = attach_kprobe_multi (obj, pattern, opts)
      if (nargin < 2)
        pattern = '';
      end
      if (nargin < 3)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_kprobe_multi', obj.ptr, pattern, opts));
    end

    function l = attach_uprobe (obj, pid, path, off, opts)
      if (nargin < 4 || isempty (off))
        off = 0;
      end
      if (nargin < 5)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_uprobe', obj.ptr, pid, path, off, opts));
    end

    function l = attach_uprobe_multi (obj, pid, path, pattern, opts)
      if (nargin < 4)
        pattern = '';
      end
      if (nargin < 5)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_uprobe_multi', obj.ptr, pid, ...
                                 path, pattern, opts));
    end

    function l = attach_tracepoint (obj, category, tname, opts)
      if (nargin < 4)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_tracepoint', obj.ptr, ...
                                 category, tname, opts));
    end

    function l = attach_raw_tracepoint (obj, tname)
      l = bpf.Link (libbpf_wrap ('program_attach_raw_tracepoint', obj.ptr, tname));
    end

    function l = attach_trace (obj)
      l = bpf.Link (libbpf_wrap ('program_attach_trace', obj.ptr));
    end

    function l = attach_lsm (obj)
      l = bpf.Link (libbpf_wrap ('program_attach_lsm', obj.ptr));
    end

    function l = attach_cgroup (obj, cgroup_fd)
      l = bpf.Link (libbpf_wrap ('program_attach_cgroup', obj.ptr, cgroup_fd));
    end

    function l = attach_netns (obj, netns_fd)
      l = bpf.Link (libbpf_wrap ('program_attach_netns', obj.ptr, netns_fd));
    end

    function l = attach_xdp (obj, ifindex)
      l = bpf.Link (libbpf_wrap ('program_attach_xdp', obj.ptr, ifindex));
    end

    function l = attach_tcx (obj, ifindex, opts)
      if (nargin < 3)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_tcx', obj.ptr, ifindex, opts));
    end

    function l = attach_netkit (obj, ifindex, opts)
      if (nargin < 3)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_netkit', obj.ptr, ifindex, opts));
    end

    function l = attach_sockmap (obj, map_fd)
      l = bpf.Link (libbpf_wrap ('program_attach_sockmap', obj.ptr, map_fd));
    end

    function l = attach_freplace (obj, target_fd, func)
      if (nargin < 3)
        func = '';
      end
      l = bpf.Link (libbpf_wrap ('program_attach_freplace', obj.ptr, target_fd, func));
    end

    function l = attach_netfilter (obj, opts)
      if (nargin < 2)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_netfilter', obj.ptr, opts));
    end

    function l = attach_iter (obj)
      l = bpf.Link (libbpf_wrap ('program_attach_iter', obj.ptr));
    end

    function l = attach_usdt (obj, pid, path, provider, name, opts)
      if (nargin < 6)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_usdt', obj.ptr, pid, path, ...
                                 provider, name, opts));
    end

    function l = attach_perf_event (obj, perf_fd, opts)
      if (nargin < 3)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_perf_event', obj.ptr, perf_fd, opts));
    end

    function l = attach_ksyscall (obj, syscall, opts)
      if (nargin < 3)
        opts = struct ();
      end
      l = bpf.Link (libbpf_wrap ('program_attach_ksyscall', obj.ptr, syscall, opts));
    end

    % --------------------------------------------------------------- run
    function r = test_run (obj, data, repeat, opts)
      if (nargin < 2)
        data = uint8 ([]);
      end
      if (nargin < 3 || isempty (repeat))
        repeat = 1;
      end
      if (nargin < 4)
        opts = struct ();
      end
      r = libbpf_wrap ('program_test_run', obj.ptr, data, repeat, opts);
    end

    function disp (obj)
      t = obj.type ();
      fprintf ('  bpf.Program "%s" section=%s type=%s fd=%d\n', ...
               obj.name, obj.section (), t.name, obj.fd ());
    end
  end
end
