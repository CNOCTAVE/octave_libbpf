function memlock (bytes)
%BPF.MEMLOCK  Raise the RLIMIT_MEMLOCK limit (for old kernels).
%
%   bpf.memlock (BYTES)
%
%   Kernels before 5.11 charged eBPF maps and programs against
%   RLIMIT_MEMLOCK; on such systems this call is required before creating
%   large maps.  It is a no-op on modern kernels but harmless.

  if (nargin < 1)
    bytes = 512 * 1024 * 1024;
  end
  bpf.raw ('set_memlock_rlim', bytes);
end
