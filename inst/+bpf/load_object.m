function obj = load_object (source, varargin)
%BPF.LOAD_OBJECT  Convenience: open, load and optionally attach an eBPF object.
%
%   OBJ = bpf.load_object (PATH)
%   OBJ = bpf.load_object (BUILDER)
%   OBJ = bpf.load_object (BYTES, NAME)
%   OBJ = bpf.load_object (..., 'attach', true)
%
%   PATH may be a .bpf.o file produced by clang, BUILDER a bpf.Builder
%   holding programs written in Octave, BYTES a uint8 ELF image.
%
%   Optionally the object is pinned with 'pin', PATH.
%
%   See also bpf.Object, bpf.Builder.

  attach = false;
  pinpath = '';
  k = 1;
  while (k <= numel (varargin))
    switch (lower (varargin{k}))
      case 'attach'
        attach = varargin{k+1};
        k = k + 2;
      case 'pin'
        pinpath = varargin{k+1};
        k = k + 2;
      otherwise
        error ('bpf:load', 'unknown option "%s"', varargin{k});
    end
  end

  if (isa (source, 'bpf.Builder'))
    obj = source.build ();
  elseif (isa (source, 'uint8') || isnumeric (source))
    if (isempty (varargin))
      error ('bpf:load', 'an in-memory image needs a name argument');
    end
    obj = bpf.Object.from_mem (uint8 (source), 'octave_bpf');
  elseif (ischar (source))
    obj = bpf.Object.from_file (source);
  else
    error ('bpf:load', 'unsupported source');
  end

  obj.load ();
  if (~ isempty (pinpath))
    obj.pin (pinpath);
  end
  if (attach)
    obj.attach_all ();
  end
end
