function id = helper (key)
%BPF.HELPER  Resolve an eBPF helper function id.
%
%   id = bpf.helper ('map_lookup_elem')
%   id = bpf.helper ('bpf_map_lookup_elem')
%   id = bpf.helper (1)
%
%   Used together with the assembler:
%
%       a.call (bpf.helper ('map_lookup_elem'));
%
%   The table is generated from libbpf's bpf_helper_defs.h and therefore
%   covers every helper known to the libbpf version the package was built
%   against.

  T = bpf.helper_table ();

  if (isnumeric (key) && isscalar (key))
    id = key;
    return;
  end
  if (~ ischar (key))
    error ('bpf:helper', 'helper name must be a string or a number');
  end

  nm = lower (key);
  if (isempty (strfind (nm, 'bpf_')))
    nm = ['bpf_' nm];
  end
  if (~ isfield (T, nm))
    error ('bpf:helper', 'unknown eBPF helper ''%s''', key);
  end
  id = T.(nm);
end
