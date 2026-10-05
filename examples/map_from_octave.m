%MAP_FROM_OCTAVE  Create and manipulate eBPF maps straight from Octave.
%
%   Run with:  pkg load octave_libbpf;  map_from_octave
%
%   Uses the low level libbpf map API, so no program has to be loaded.

pkg load octave_libbpf

% a hash map with 4 byte keys and 8 byte values, created by the kernel
m = bpf.Map.create ('hash', 4, 8, 16, 'octave_hash');
disp (m);
printf ('kernel name: %s\n', m.info ().name);

for k = 0:4
  m.update (k, 100 + k);
end

printf ('m[3] = %d\n', m.lookup (3));
printf ('keys: %s\n', mat2str (cell2mat (m.keys ())));
printf ('values: %s\n', mat2str (cellfun (@(k) m.lookup (k), m.keys ())));

m.remove (3);
printf ('after remove(3): %s\n', mat2str (cell2mat (m.keys ())));

% raw byte level access
m.update (uint8 ([9 0 0 0]), uint8 (1:8));
printf ('raw m[9] = %s\n', mat2str (m.lookup (9, 'raw')));

% an array map cannot be resized and does not support removal
a = bpf.Map.create ('array', 4, 4, 4, 'octave_array');
a.update (2, 42);
a.freeze ();
printf ('frozen array a[2] = %d\n', a.lookup (2));

clear a m
