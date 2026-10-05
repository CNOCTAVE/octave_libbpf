#!/usr/bin/env python3
"""Generate inst/+bpf/enum_table.m from the Linux UAPI <linux/bpf.h>.

libbpf exposes the numeric values of the kernel enums to userspace, but the
m-code layer wants to accept friendly names such as 'array' or 'ringbuf'.  The
tables are parsed straight out of the vendored UAPI header so that they stay in
sync with the kernel definitions used at build time.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.normpath(os.path.join(HERE, '..', '..', 'inst', '+bpf'))

CANDIDATES = [
    os.path.join(HERE, '..', 'vendor', 'linux', 'bpf.h'),
    '/usr/include/linux/bpf.h',
]

WANTED = [
    'bpf_map_type',
    'bpf_prog_type',
    'bpf_attach_type',
    'bpf_link_type',
    'bpf_func_id',
    'bpf_stats_type',
    'bpf_cmd',
    'bpf_map_lookup_flags',
    'bpf_attach_type',
    'libbpf_pin_type',
]

ENUM_RE = re.compile(r'enum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\n\s*\}', re.S)


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    return text


def parse_enums(path):
    text = strip_comments(open(path).read())
    out = {}
    for m in ENUM_RE.finditer(text):
        name = m.group(1)
        body = m.group(2)
        vals = []
        cur = 0
        for item in body.split(','):
            item = item.strip()
            if not item:
                continue
            item = item.split('=')[0].strip() if '=' not in item else item
            if '=' in item:
                ident, val = item.split('=', 1)
                ident = ident.strip()
                val = val.strip()
            else:
                ident, val = item, None
            if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', ident):
                continue
            if val is not None:
                try:
                    cur = int(val, 0)
                except ValueError:
                    continue
            vals.append((ident, cur))
            cur += 1
        if vals:
            out.setdefault(name, [])
            out[name].extend(vals)
    return out


def main():
    src = None
    for c in CANDIDATES:
        if os.path.exists(c):
            src = c
            break
    if src is None:
        sys.stderr.write('linux/bpf.h not found; keeping existing table\n')
        return 0

    enums = parse_enums(src)
    lines = []
    lines.append('function T = enum_table ()\n')
    lines.append('%BPF.ENUM_TABLE  Numeric values of the Linux eBPF enums.\n')
    lines.append('%\n')
    lines.append('%   Generated from <linux/bpf.h> by src/tools/gen_enums.py.\n')
    lines.append('%   Do not edit by hand.\n\n')
    lines.append('  persistent tbl;\n')
    lines.append('  if (isempty (tbl))\n')
    lines.append('    tbl = struct ();\n')
    total = 0
    for name in WANTED:
        if name not in enums:
            continue
        lines.append('    T.%s = struct ();\n' % name)
        seen = set()
        for ident, val in enums[name]:
            if ident in seen:
                continue
            seen.add(ident)
            lines.append('    tbl.%s.%s = %d;\n' % (name, ident, val))
            total += 1
    lines.append('  end\n')
    lines.append('  T = tbl;\n')
    lines.append('end\n')
    with open(os.path.join(INST, 'enum_table.m'), 'w') as fh:
        fh.write(''.join(lines))
    print('enum_table.m: %d constants from %s' % (total, src))
    return 0


if __name__ == '__main__':
    sys.exit(main())
