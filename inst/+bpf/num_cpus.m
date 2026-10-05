function n = num_cpus ()
%BPF.NUM_CPUS  Number of possible CPUs, as used to size per-CPU maps.
%
%   N = bpf.num_cpus ()

  n = bpf.raw ('num_possible_cpus');
end
