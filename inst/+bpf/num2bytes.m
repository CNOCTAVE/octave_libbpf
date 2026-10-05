function b = num2bytes (v, n)
%BPF.NUM2BYTES  Convert an integer into a little endian byte vector.
%
%   B = bpf.num2bytes (V)      little endian bytes of V, width taken from V
%   B = bpf.num2bytes (V, N)   exactly N bytes (N = 1, 2, 4 or 8)
%
%   A uint8 row vector is passed through; it is truncated or zero extended
%   when N is given.

  if (isa (v, 'uint8') && isrow (v))
    b = v;
    if (nargin > 1 && numel (b) ~= n)
      if (numel (b) > n)
        b = b(1:n);
      else
        b = [b, zeros(1, n - numel (b), 'uint8')];
      end
    end
    return;
  end

  if (nargin < 2 || isempty (n))
    if (isa (v, 'uint64') || isa (v, 'int64') || (isscalar (v) && abs (v) > 2^32))
      n = 8;
    elseif (isa (v, 'uint32') || isa (v, 'int32'))
      n = 4;
    elseif (isa (v, 'uint16') || isa (v, 'int16'))
      n = 2;
    elseif (isa (v, 'uint8') || isa (v, 'int8'))
      n = 1;
    else
      v = double (v);
      if (v < 0)
        n = 8;
      elseif (v > 2^32 - 1)
        n = 8;
      elseif (v > 2^16 - 1)
        n = 4;
      else
        n = 4;
      end
    end
  end

  switch (n)
    case 1, t = 'uint8';
    case 2, t = 'uint16';
    case 4, t = 'uint32';
    case 8, t = 'uint64';
    otherwise
      error ('bpf:num2bytes', 'unsupported width %d', n);
  end

  if (v < 0)
    v = typecast (cast (v, ['int' num2str(n * 8)]), t);
  else
    v = cast (v, t);
  end
  b = typecast (v, 'uint8');
  b = b(1:n);
end
