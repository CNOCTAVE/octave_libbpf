function [value, name] = enum_lookup (group, key, prefix)
%BPF.ENUM_LOOKUP  Resolve a kernel eBPF enum by name or number.
%
%   [V, NAME] = bpf.enum_lookup (GROUP, KEY)
%   [V, NAME] = bpf.enum_lookup (GROUP, KEY, PREFIX)
%
%   GROUP is a field of bpf.enum_table (for example 'bpf_map_type'), KEY is
%   either a numeric value or a (possibly abbreviated) name.  Names are
%   matched case insensitively, with and without the canonical PREFIX; so
%   'array', 'ARRAY' and 'BPF_MAP_TYPE_ARRAY' all resolve to 2.
%
%   This function is mainly used internally by bpf.map_type, bpf.prog_type
%   and friends.

  T = bpf.enum_table ();

  if (~ isfield (T, group))
    error ('bpf:enum_lookup', 'unknown enum group ''%s''', group);
  end
  E = T.(group);
  flds = fieldnames (E);

  if (nargin < 3)
    prefix = '';
  end

  if (isnumeric (key) && isscalar (key))
    value = key;
    name = '';
    for k = 1:numel (flds)
      if (E.(flds{k}) == key)
        name = flds{k};
        break;
      end
    end
    return;
  end

  if (~ ischar (key))
    error ('bpf:enum_lookup', 'KEY must be a name or a number');
  end

  cand = upper (key);
  if (isempty (prefix))
    % derive a prefix from the field names themselves
    allnames = flds;
  else
    allnames = {upper(prefix)};
  end

  tries = {cand};
  for k = 1:numel (allnames)
    pfx = allnames{k};
    if (~ isempty (pfx) && pfx(end) ~= '_')
      pfx = [pfx '_'];
    end
    tries{end+1} = [pfx cand];                    %#ok<AGROW>
  end
  % strip a leading BPF_ from the canonical prefix for the short form
  short = regexprep (cand, '^BPF_', '');

  for k = 1:numel (tries)
    idx = find (strcmp (flds, tries{k}), 1);
    if (~ isempty (idx))
      value = E.(flds{idx});
      name = flds{idx};
      return;
    end
  end

  % last resort: match the short form against field names whose prefix is
  % stripped, so that 'BPF_MAP_TYPE_HASH' and 'hash' both work.
  for k = 1:numel (flds)
    stripped = regexprep (flds{k}, '^BPF_[A-Z0-9_]*?_(?=[A-Z0-9]+$)', '');
    if (strcmp (stripped, short) || strcmp (flds{k}, cand))
      value = E.(flds{k});
      name = flds{k};
      return;
    end
  end

  error ('bpf:enum_lookup', 'unknown %s name ''%s''', group, key);
end
