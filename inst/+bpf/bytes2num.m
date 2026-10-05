function v = bytes2num (b, signed)
%BPF.BYTES2NUM  Convert a little endian byte vector into an integer.
%
%   V = bpf.bytes2num (BYTES)          unsigned result
%   V = bpf.bytes2num (BYTES, SIGNED)  signed result when SIGNED is true
%
%   BYTES is a uint8 row vector of 1, 2, 4 or 8 elements as produced by the
%   kernel.  Zero length input yields [] and longer input is returned
%   unchanged as a uint8 row vector.

  if (nargin < 2)
    signed = false;
  end
  b = uint8 (b(:)');
  n = numel (b);
  switch (n)
    case 0
      v = [];
    case 1
      v = typecast (b, 'uint8');
    case 2
      v = typecast (b, 'uint16');
    case 4
      v = typecast (b, 'uint32');
    case 8
      v = typecast (b, 'uint64');
    otherwise
      v = b;
      return;
  end
  if (signed && n > 1)
    v = typecast (v, ['int' num2str(n * 8)]);
  end
end
