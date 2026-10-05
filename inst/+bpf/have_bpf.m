function tf = have_bpf ()
%BPF.HAVE_BPF  True when this process may load eBPF programs and maps.
%
%   TF = bpf.have_bpf () probes the kernel by creating a tiny array map.
%   It returns false when the process lacks CAP_BPF/CAP_SYS_ADMIN or when
%   the kernel has BPF disabled, so callers can skip privileged work.
%
%   See also bpf.probe.

  persistent cached
  if (~ isempty (cached))
    tf = cached;
    return;
  end
  tf = false;
  try
    f = libbpf_wrap ('map_create', bpf.map_type ('array'), ...
                     'octave_probe', 4, 4, 1, struct ());
    libbpf_wrap ('close_fd', f);
    tf = true;
  catch
    tf = false;
  end
  cached = tf;
end
