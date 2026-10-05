# Design notes

This document describes how `octave_libbpf` turns Octave m-code into a
kernel-loadable eBPF object, and how the C++ binding is organised.  It is meant
for people extending the package.

## Layers

```
      user m-code
          |          bpf.Builder / bpf.Asm / bpf.Insn
          v
   ELF64/BPF image  <-- bpf.Elf + bpf.BtfBuilder
          |
          v
     libbpf_wrap    (src/libbpf_wrap.cc, one oct-file, ~180 subcommands)
          |
          v
        libbpf      (system libbpf.so / libbpf.so.1)
          |
          v
      bpf(2) syscalls
```

Everything above `libbpf_wrap` is plain m-code; everything below it is the
system libbpf.  The C++ layer keeps no policy: it converts Octave values to C,
calls libbpf, converts results back, and maps negative errno values to Octave
errors with `libbpf_strerror()` text.

## The oct-file

`libbpf_wrap (COMMAND, ARG, ...)` dispatches on a string to one of the handlers
in `g_table`.  Conventions:

* **Handles** are `struct bpf_*` pointers passed as `uint64` scalars.
* **Errors** raise an Octave error whose message starts with `libbpf:`.
  Pointer returning libbpf calls are checked with `libbpf_get_error()`.
* **Optional options** are passed as an Octave scalar struct; handlers read
  fields through the `Opts` helper, which returns defaults for absent fields.
* **Binary data** is passed and returned as `uint8` row vectors.
* **Lifetime**: objects created from memory own a `malloc`ed copy of the ELF
  image, because libbpf keeps an `elf_memory()` reference to it until
  `bpf_object__close()`; the copy is freed by the same call.
* **Callbacks**: ring buffer and perf buffer samples are collected by C
  callbacks into a `std::vector<octave_value>` and returned to Octave *after*
  `ring_buffer__poll()`/`perf_buffer__poll()` returns.  The interpreter is
  therefore never re-entered from inside libbpf.

### Bundled headers

The public libbpf headers are large and versioned in lockstep with the library,
so the package bundles them under `src/vendor/`.  `src/Makefile` prefers, in
order: an explicit `LIBBPF_ROOT`, a `libbpf/` source tree next to the package,
`/usr/include/bpf`, and finally the bundled copy.  The Linux UAPI headers
(`<linux/bpf.h>`, `<linux/btf.h>`, …) also come from `src/vendor` when the
system does not provide them.

Because a distribution `libbpf` package often installs only `libbpf.so.1`
(no `.so` development symlink, no `libbpf.pc`), the Makefile links with
`-l:libbpf.so.1` as a fallback.  libbpf guarantees that public structs only ever
grow by appending fields, so a package built against newer headers keeps working
against an older shared library: every options struct is zero initialised and
`schema.sz` is set to the header's `sizeof`, which libbpf validates.

## Generating eBPF objects

### Instructions

`bpf.Insn` encodes one `struct bpf_insn` (8 bytes, little endian:

```
byte 0     code
byte 1     dst_reg (low nibble) | src_reg (high nibble)
bytes 2-3  int16 off
bytes 4-7  int32 imm
```
)

The mnemonic grammar is `{op}{64|32}_{imm|reg}` for ALU operations,
`{jcc}_{imm|reg}` / `jmp32_{jcc}_{imm|reg}` for branches, `{ldx,stx,st}_{w,h,b,dw}`
for memory access, plus the special forms (`call`, `ja`, `exit`, `end_le`,
`atomic_*`, `ld_imm64`, `ld_map_fd`, …).

`bpf.Asm` accumulates instructions, records label definitions and patch
positions, and resolves the branch offsets when `bytes()` is called.  A
relocation is recorded whenever a map is referenced.

### BTF

Maps are described the way libbpf 1.0+ requires: an anonymous struct in the
`.maps` DATASEC whose members are found by name.

```
struct {
    int (*type)[BPF_MAP_TYPE_ARRAY];   /* __uint(type, ...)   */
    int (*max_entries)[8];             /* __uint(max_entries) */
    __u32 *key;                        /* __type(key, __u32)  */
    __u64 *value;                      /* __type(value, __u64)*/
} counts SEC(".maps");
```

Note that `__uint(name, val)` expands to `int (*name)[val]`, so libbpf reads
the member's *array length* with `get_map_field_int()`; `__type(name, val)`
expands to `val *name`, a pointer whose pointee gives the key/value size and
BTF type id.  `bpf.BtfBuilder` emits exactly this shape:

* `type`, `max_entries`, `map_flags`, `numa_node`, `key_size`, `value_size`,
  `pinning` are `PTR -> ARRAY[n] of INT`
* `key`/`value` are `PTR -> <key/value type>` (omitted for ring buffers, which
  require `key_size == value_size == 0`)
* one `VAR` per map with `BTF_VAR_GLOBAL_ALLOCATED` linkage
* one `DATASEC ".maps"` listing every VAR with its offset and size

Two details are easy to get wrong and are handled explicitly:

* the *unused* `size`/`type` union member of a `BTF_KIND_ARRAY` must be zero —
  the kernel rejects the whole blob with `size != 0` otherwise;
* the `encoding` word of a `BTF_KIND_INT` carries the bit width, not the byte
  size (`nr_bits`).

### ELF

`bpf.Elf` writes an ELF64 little endian `ET_REL` object for `EM_BPF` (247) with:

```
0  NULL
1  .strtab                        symbol names
2  .shstrtab                      section names
3+ program sections               SHT_PROGBITS, SHF_ALLOC|SHF_EXECINSTR, align 8
   .maps                          SHT_PROGBITS, SHF_ALLOC|SHF_WRITE,  align 8
   license                        SHT_PROGBITS, "GPL\0"
   .BTF                           SHT_PROGBITS
   .symtab                        local symbols first (section symbols)
   .rel<section>                  one per program, SHT_REL, SHF_INFO_LINK
```

Programs are discovered by libbpf as `STT_FUNC` `STB_GLOBAL` symbols whose
`st_shndx` is an executable section and whose `st_size` is non-zero.  Map
references become `R_BPF_64_64` relocations against the map's `STT_OBJECT`
symbol at the byte offset of the `ld_imm64` slot.

The byte order matters: an `N x 8` instruction matrix must be flattened in
*instruction* order, not column-major, when it is written to the section.

## Adding an entry point

1. Add a `HANDLER (h_xxx)` in `src/libbpf_wrap.cc` and register it in
   `g_table`.
2. Wrap it in m-code under `inst/+bpf/` if it is user facing.
3. Run `python3 src/tools/gen_helpers.py` and `gen_enums.py` only when the
   vendored headers change — they regenerate `helper_table.m` and
   `enum_table.m`.
4. `python3 src/tools/gen_asm.py` regenerates `inst/+bpf/Asm.m` from the
   mnemonic list; edit the generator, never the generated file.

## Octave classdef gotchas

The m-code in this package works around a few Octave behaviours that are worth
knowing when editing it:

* `obj.prop = [obj.prop, uint8 (x), uint8 (0)]` is mis-parsed inside class
  methods; build the value in a local variable first.
* a `persistent` variable may not share its name with the function's output
  argument.
* `do` and `end` are keywords and cannot name methods; the assembler therefore
  dispatches through `ins()`.
* file names are case sensitive for Octave but not on every file system, so
  `bpf.BTF` (the introspection class) and `bpf.BtfBuilder` (the encoder) must
  not differ only in case.
* inside a cell or matrix literal, a function call written with a space before
  the parenthesis is parsed as *command syntax* and the remaining comma
  separated items become extra arguments:

  ```octave
  { fullfile ('/tmp'), 2 }     % 1x3 cell: command syntax, not a 1x2 cell!
  {fullfile('/tmp'), 2}        % 1x2 cell, as intended
  ```

  Write `f(x)` without the space there (this is an Octave parser quirk, not a
  package restriction).
* `pkg.function (args).field` does not parse when `pkg.function` is a package
  function; assign the result to a variable first.  This is why
  `bpf.map_type()` returns the numeric value and provides the name as a second
  output instead of returning a struct.
