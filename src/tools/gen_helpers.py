#!/usr/bin/env python3
"""Generate inst/+bpf/helper_table.m from libbpf's bpf_helper_defs.h.

The helper identifiers (BPF_FUNC_*) are a large, purely mechanical table;
generating them keeps bpf.helper() complete without hand transcription.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.normpath(os.path.join(HERE, '..', '..', 'inst', '+bpf'))

CANDIDATES = [
    os.path.join(HERE, '..', 'vendor', 'bpf', 'bpf_helper_defs.h'),
    os.path.join(HERE, '..', '..', '..', 'libbpf', 'src', 'bpf_helper_defs.h'),
    '/usr/include/bpf/bpf_helper_defs.h',
]

PATTERN = re.compile(
    r'static\s+[^;=]*?\(\s*\*\s*const\s+(bpf_[A-Za-z0-9_]+)\s*\)'
    r'\s*\([^;]*?\)\s*=\s*\(void\s*\*\s*\)\s*(\d+)\s*;',
    re.S)


def find_source():
    for c in CANDIDATES:
        if os.path.exists(c):
            return os.path.normpath(c)
    return None


def main():
    src = find_source()
    if src is None:
        sys.stderr.write('bpf_helper_defs.h not found; keeping existing table\n')
        return 0
    text = open(src).read()
    pairs = {}
    for m in PATTERN.finditer(text):
        pairs[m.group(1)] = int(m.group(2))
    if len(pairs) < 50:
        sys.stderr.write('only %d helpers parsed from %s; refusing to write\n'
                         % (len(pairs), src))
        return 1

    lines = []
    lines.append('function T = helper_table ()\n')
    lines.append('%BPF.HELPER_TABLE  Mapping of eBPF helper names to helper ids.\n')
    lines.append('%\n')
    lines.append('%   Generated from libbpf bpf_helper_defs.h by src/tools/gen_helpers.py.\n')
    lines.append('%   Do not edit by hand.\n\n')
    lines.append('  persistent tbl;\n')
    lines.append('  if (isempty (tbl))\n')
    lines.append('    tbl = struct ();\n')
    for name in sorted(pairs, key=lambda n: pairs[n]):
        lines.append("    tbl.%s = %d;\n" % (name, pairs[name]))
    lines.append('  end\n')
    lines.append('  T = tbl;\n')
    lines.append('end\n')
    with open(os.path.join(INST, 'helper_table.m'), 'w') as fh:
        fh.write(''.join(lines))
    print('helper_table.m: %d helpers from %s' % (len(pairs), src))
    return 0


if __name__ == '__main__':
    sys.exit(main())
