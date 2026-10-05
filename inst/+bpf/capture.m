function tf = capture (tf_in)
%BPF.CAPTURE  Enable or disable capturing of libbpf diagnostics.
%
%   TF = bpf.capture ()        report the current setting
%   bpf.capture (TF)           change it
%
%   When capturing is enabled (the default) everything libbpf prints is kept
%   and can be retrieved with bpf.log.

  if (nargin < 1)
    tf = true;
  else
    bpf.raw ('set_capture', logical (tf_in));
    tf = logical (tf_in);
  end
end
