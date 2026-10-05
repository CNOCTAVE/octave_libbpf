function c = commands ()
%BPF.COMMANDS  List the commands accepted by the libbpf_wrap oct-file.
%
%   C = bpf.commands () returns a cellstr with every command name, sorted
%   alphabetically.  See bpf.raw for how to call them.

  persistent tbl
  if (isempty (tbl))
    tbl = libbpf_wrap ('commands');
  end
  c = tbl;
end
