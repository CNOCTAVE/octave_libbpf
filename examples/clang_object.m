%CLANG_OBJECT  Load a .bpf.o produced by clang from Octave.
%
%   Run with:  pkg load octave_libbpf;  clang_object
%
%   bpf.Object is not limited to Octave authored programs: any eBPF ELF
%   object works, here one compiled from C with clang.  This is the
%   traditional libbpf workflow, just driven from Octave instead of C.
%
%   Compile the reference program with (needs clang and the libbpf headers):
%
%     clang -target bpf -g -O2 -c hello.bpf.c -o hello.bpf.o

pkg load octave_libbpf

here = fileparts (mfilename ('fullpath'));
% note: no space between a function name and '(' inside a cell literal,
% otherwise Octave parses the comma separated items as command arguments
candidates = {fullfile(here, 'hello.bpf.o'), ...
              fullfile(here, '..', 'examples', 'hello.bpf.o')};
fpath = '';
for k = 1:numel (candidates)
  if (exist (candidates{k}, 'file'))
    fpath = candidates{k};
    break;
  end
end

if (isempty (fpath))
  printf ('No hello.bpf.o found; compile examples/hello.bpf.c first:\n');
  printf ('  clang -target bpf -g -O2 -c examples/hello.bpf.c -o examples/hello.bpf.o\n');
  return;
end

obj = bpf.Object.from_file (fpath);
disp (obj);
obj.load ();
disp (obj);

for m = obj.maps ()
  disp (m{1});
end

clear obj
