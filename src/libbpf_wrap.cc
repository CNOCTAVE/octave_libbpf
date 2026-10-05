// SPDX-License-Identifier: BSD-2-Clause
//
// libbpf_wrap.cc -- GNU Octave bindings for libbpf.
//
// The oct-file exposes a single Octave visible function,
//
//     libbpf_wrap (COMMAND, ARG, ...)
//
// which dispatches on the string COMMAND to one of the C handlers below.
// All libbpf pointers are passed back and forth as uint64 scalars; lifetime
// management is the responsibility of the m-code layer (see inst/+bpf).
// A registry of the pointers handed out is kept so that the m-code layer can
// validate handles, and so that memory owned by the wrapper (in particular
// the in-memory ELF images handed to bpf_object__open_mem, which libbpf
// references until the object is closed) can be released at the right time.
//
// Copyright (C) 2024-2026 Yu Hongbo

#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <map>
#include <mutex>
#include <string>
#include <vector>
#include <type_traits>

#include <octave/oct.h>
#include <octave/Cell.h>
#include <octave/oct-map.h>
#include <octave/ov-struct.h>
#include <octave/parse.h>

#if defined(__has_include)
#  if __has_include(<bpf/libbpf.h>)
#    include <bpf/libbpf.h>
#    include <bpf/bpf.h>
#    include <bpf/btf.h>
#    define BPF_HAVE_BPF_DIR 1
#  endif
#endif

#ifndef BPF_HAVE_BPF_DIR
#  include <libbpf.h>
#  include <bpf.h>
#  include <btf.h>
#endif

// ---------------------------------------------------------------------------
// Forward declarations for libbpf entry points that only exist in newer
// libbpf releases.  Declaring them weak lets us probe for them at run time and
// keep working against the older shared library.
// ---------------------------------------------------------------------------

// Some entry points only exist in newer libbpf releases.  Declaring them weak
// lets the wrapper probe for them at run time and keep working against an
// older shared library.
extern "C" {
extern struct bpf_link *
bpf_program__attach_tracing_multi (const struct bpf_program *,
                                   const char *,
                                   const struct bpf_tracing_multi_opts *)
  __attribute__ ((weak));
extern struct bpf_link *
bpf_map__attach_cgroup_opts (const struct bpf_map *, int,
                             const struct bpf_cgroup_opts *)
  __attribute__ ((weak));
extern int
bpf_map__set_exclusive_program (struct bpf_map *, struct bpf_program *)
  __attribute__ ((weak));
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

namespace {

using std::string;

[[noreturn]] void
fail (const string& msg)
{
  error ("libbpf: %s", msg.c_str ());
}

[[noreturn]] void
fail_errno (const string& where, long err)
{
  char buf[256] = { 0 };
  int e = (err > 0) ? static_cast<int> (err) : static_cast<int> (-err);
  libbpf_strerror (e, buf, sizeof (buf) - 1);
  if (buf[0] == '\0')
    std::snprintf (buf, sizeof (buf), "%s", std::strerror (e));
  fail (where + ": " + buf + " (" + std::to_string (e) + ")");
}

inline bool
has (const octave_value_list& a, int i)
{
  return i >= 0 && i < a.length ();
}

const octave_value&
arg_at (const octave_value_list& a, int i, const char *nm)
{
  if (! has (a, i))
    fail (string ("missing argument '") + nm + "'");
  return a(i);
}

string
arg_str (const octave_value_list& a, int i, const char *nm)
{
  const octave_value& v = arg_at (a, i, nm);
  if (! v.is_string ())
    fail (string ("argument '") + nm + "' must be a string");
  return v.string_value ();
}

string
opt_str (const octave_value_list& a, int i, const string& def)
{
  if (! has (a, i) || a(i).isempty ())
    return def;
  if (! a(i).is_string ())
    fail ("expected a string argument");
  return a(i).string_value ();
}

uint64_t
arg_u64 (const octave_value_list& a, int i, const char *nm)
{
  const octave_value& v = arg_at (a, i, nm);
  if (v.is_uint64_type ())
    return v.uint64_scalar_value ().value ();
  if (v.is_int64_type ())
    return static_cast<uint64_t> (v.int64_scalar_value ().value ());
  return static_cast<uint64_t> (v.uint64_value ());
}

long
arg_long (const octave_value_list& a, int i, const char *nm)
{
  return static_cast<long> (arg_u64 (a, i, nm));
}

long
opt_long (const octave_value_list& a, int i, long def)
{
  if (! has (a, i) || a(i).isempty ())
    return def;
  return arg_long (a, i, "arg");
}

bool
opt_bool (const octave_value_list& a, int i, bool def)
{
  if (! has (a, i) || a(i).isempty ())
    return def;
  return a(i).bool_value ();
}

octave_value
u64v (uint64_t v)
{
  return octave_value (octave_uint64 (v));
}

octave_value
intv (long v)
{
  return octave_value (static_cast<double> (v));
}

octave_value
strv (const char *s)
{
  return octave_value (s ? string (s) : string ());
}

//! Extract a raw byte buffer from a uint8/int8/char array or a string.
string
arg_bytes (const octave_value_list& a, int i, const char *nm)
{
  const octave_value& v = arg_at (a, i, nm);
  if (v.is_string ())
    return v.string_value ();
  if (v.isempty ())
    return string ();
  if (! v.isnumeric ())
    fail (string ("argument '") + nm + "' must be a numeric array or a string");
  NDArray d = v.array_value ();
  octave_idx_type n = d.numel ();
  string out (static_cast<size_t> (n), '\0');
  const double *p = d.data ();
  for (octave_idx_type k = 0; k < n; k++)
    out[static_cast<size_t> (k)] = static_cast<char> (static_cast<unsigned char> (p[k]));
  return out;
}

//! Build a 1xN uint8 row vector from a raw buffer.
octave_value
bytes_value (const void *p, size_t n)
{
  dim_vector dv (1, static_cast<octave_idx_type> (n));
  uint8NDArray out (dv);
  unsigned char *q = reinterpret_cast<unsigned char *> (out.fortran_vec ());
  if (p && n)
    std::memcpy (q, p, n);
  else if (n)
    std::memset (q, 0, n);
  return octave_value (out);
}

//! Optional options struct, given as an Octave scalar struct.
class Opts
{
public:
  Opts () : m_valid (false) { }

  Opts (const octave_value_list& a, int i)
    : m_valid (false)
  {
    if (has (a, i) && a(i).isstruct () && ! a(i).isempty ())
      {
        m_map = a(i).scalar_map_value ();
        m_valid = m_map.nfields () > 0;
      }
  }

  bool valid () const { return m_valid; }

  bool got (const char *f) const
  {
    return m_valid && m_map.contains (f)
           && ! m_map.getfield (f).isempty ();
  }

  double num (const char *f, double def = 0) const
  {
    if (! got (f))
      return def;
    return m_map.getfield (f).double_value ();
  }

  bool flag (const char *f, bool def = false) const
  {
    if (! got (f))
      return def;
    return m_map.getfield (f).bool_value ();
  }

  string str (const char *f, const string& def = string ()) const
  {
    if (! got (f))
      return def;
    return m_map.getfield (f).string_value ();
  }

  Cell cell (const char *f) const
  {
    if (! got (f))
      return Cell ();
    return m_map.getfield (f).cell_value ();
  }

private:
  octave_scalar_map m_map;
  bool m_valid;
};

// ---------------------------------------------------------------------------
// Handle registry and wrapper owned memory
// ---------------------------------------------------------------------------

std::mutex g_mutex;
std::map<uint64_t, string> g_registry;
std::map<uint64_t, void *> g_owned_buffers;   // objects opened from memory
std::map<uint64_t, string> g_log_buffers;     // verifier log buffers

void
reg_add (const void *p, const string& kind)
{
  if (! p)
    return;
  std::lock_guard<std::mutex> lock (g_mutex);
  g_registry[reinterpret_cast<uint64_t> (p)] = kind;
}

void
reg_del (const void *p)
{
  if (! p)
    return;
  std::lock_guard<std::mutex> lock (g_mutex);
  auto it = g_registry.find (reinterpret_cast<uint64_t> (p));
  if (it != g_registry.end ())
    g_registry.erase (it);
  auto bt = g_owned_buffers.find (reinterpret_cast<uint64_t> (p));
  if (bt != g_owned_buffers.end ())
    {
      std::free (bt->second);
      g_owned_buffers.erase (bt);
    }
}

template <typename T>
T *
checked (uint64_t h, const char *kind)
{
  if (h == 0)
    fail ("null handle");
  T *p = reinterpret_cast<T *> (h);
  (void) kind;
  return p;
}

// ---------------------------------------------------------------------------
// libbpf print redirection
// ---------------------------------------------------------------------------

int g_print_level = 1;   // 0 = silent, 1 = warn, 2 = +info, 3 = +debug
bool g_capture = true;
string g_capture_buf;
string g_capture_buf_prev;
size_t g_capture_max = 256 * 1024;

int
print_cb (enum libbpf_print_level level, const char *fmt, va_list args)
{
  if (g_print_level <= static_cast<int> (level))
    {
      va_list ap;
      va_copy (ap, args);
      std::vfprintf (stderr, fmt, ap);
      va_end (ap);
    }

  if (g_capture)
    {
      char tmp[1024];
      va_list ap;
      va_copy (ap, args);
      int n = std::vsnprintf (tmp, sizeof (tmp), fmt, ap);
      va_end (ap);
      std::lock_guard<std::mutex> lock (g_mutex);
      g_capture_buf.append (tmp, n > 0 ? static_cast<size_t> (n) : 0);
      if (g_capture_buf.size () > g_capture_max)
        g_capture_buf.erase (0, g_capture_buf.size () - g_capture_max);
    }
  return 0;
}

bool g_init_done = false;

void
ensure_init ()
{
  if (! g_init_done)
    {
      libbpf_set_print (print_cb);
      g_init_done = true;
    }
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// Handlers: macros
// ---------------------------------------------------------------------------

#define HANDLER(name)                                                         \
  static octave_value_list name (const octave_value_list& a, int nargout)

#define RET(v)                                                                \
  do                                                                          \
    {                                                                         \
      octave_value_list rv (1);                                               \
      rv(0) = (v);                                                            \
      return rv;                                                              \
    }                                                                         \
  while (0)

#define RET0()                                                                \
  do                                                                          \
    {                                                                         \
      return octave_value_list ();                                            \
    }                                                                         \
  while (0)

// Pointer returning libbpf calls signal failure through libbpf_get_error().
#define PTR_CHECK(expr, what)                                                 \
  ({                                                                          \
    void *__p = reinterpret_cast<void *> (expr);                              \
    long __e = libbpf_get_error (__p);                                        \
    if (__e)                                                                  \
      fail_errno (what, __e);                                                 \
    __p;                                                                      \
  })

#define INT_CHECK(expr, what)                                                 \
  ({                                                                          \
    long __r = static_cast<long> (expr);                                      \
    if (__r < 0)                                                              \
      fail_errno (what, __r);                                                 \
    __r;                                                                      \
  })

namespace {

// ===========================================================================
// Version / misc
// ===========================================================================

HANDLER (h_version)
{
  octave_scalar_map m;
  m.assign ("major", octave_value (static_cast<double> (libbpf_major_version ())));
  m.assign ("minor", octave_value (static_cast<double> (libbpf_minor_version ())));
  m.assign ("string", octave_value (string (libbpf_version_string ())));
  RET (octave_value (m));
}

HANDLER (h_strerror)
{
  long e = arg_long (a, 0, "err");
  char buf[256] = { 0 };
  if (libbpf_strerror (static_cast<int> (e), buf, sizeof (buf) - 1))
    std::snprintf (buf, sizeof (buf), "%s", std::strerror (static_cast<int> (-e)));
  RET (octave_value (string (buf)));
}

HANDLER (h_type_str)
{
  string kind = arg_str (a, 0, "kind");
  long v = arg_long (a, 1, "value");
  const char *s = nullptr;
  if (kind == "prog_type")
    s = libbpf_bpf_prog_type_str (static_cast<enum bpf_prog_type> (v));
  else if (kind == "map_type")
    s = libbpf_bpf_map_type_str (static_cast<enum bpf_map_type> (v));
  else if (kind == "attach_type")
    s = libbpf_bpf_attach_type_str (static_cast<enum bpf_attach_type> (v));
  else if (kind == "link_type")
    s = libbpf_bpf_link_type_str (static_cast<enum bpf_link_type> (v));
  else
    fail ("type_str: unknown kind '" + kind + "'");
  RET (strv (s));
}

HANDLER (h_set_print_level)
{
  g_print_level = static_cast<int> (arg_long (a, 0, "level"));
  RET0 ();
}

HANDLER (h_get_print_level)
{
  RET (intv (g_print_level));
}

HANDLER (h_commands);

HANDLER (h_set_capture)
{
  g_capture = opt_bool (a, 0, true);
  {
    std::lock_guard<std::mutex> lock (g_mutex);
    g_capture_buf.clear ();
  }
  RET0 ();
}

HANDLER (h_get_log)
{
  string out;
  {
    std::lock_guard<std::mutex> lock (g_mutex);
    out = g_capture_buf;
  }
  RET (octave_value (out));
}

HANDLER (h_clear_log)
{
  std::lock_guard<std::mutex> lock (g_mutex);
  g_capture_buf.clear ();
  RET0 ();
}

HANDLER (h_probe_prog_type)
{
  long t = arg_long (a, 0, "prog_type");
  int r = libbpf_probe_bpf_prog_type (static_cast<enum bpf_prog_type> (t), nullptr);
  if (r < 0)
    fail_errno ("probe_prog_type", r);
  RET (octave_value (r > 0));
}

HANDLER (h_probe_map_type)
{
  long t = arg_long (a, 0, "map_type");
  int r = libbpf_probe_bpf_map_type (static_cast<enum bpf_map_type> (t), nullptr);
  if (r < 0)
    fail_errno ("probe_map_type", r);
  RET (octave_value (r > 0));
}

HANDLER (h_probe_helper)
{
  long pt = arg_long (a, 0, "prog_type");
  long id = arg_long (a, 1, "helper_id");
  int r = libbpf_probe_bpf_helper (static_cast<enum bpf_prog_type> (pt),
                                   static_cast<enum bpf_func_id> (id), nullptr);
  if (r < 0)
    fail_errno ("probe_helper", r);
  RET (octave_value (r > 0));
}

HANDLER (h_num_possible_cpus)
{
  int r = libbpf_num_possible_cpus ();
  if (r < 0)
    fail_errno ("num_possible_cpus", r);
  RET (intv (r));
}

HANDLER (h_prog_type_by_name)
{
  string name = arg_str (a, 0, "name");
  enum bpf_prog_type pt;
  enum bpf_attach_type at;
  int r = libbpf_prog_type_by_name (name.c_str (), &pt, &at);
  if (r < 0)
    fail_errno ("prog_type_by_name", r);
  octave_scalar_map m;
  m.assign ("prog_type", octave_value (static_cast<double> (pt)));
  m.assign ("expected_attach_type", octave_value (static_cast<double> (at)));
  m.assign ("prog_type_str", strv (libbpf_bpf_prog_type_str (pt)));
  m.assign ("attach_type_str", strv (libbpf_bpf_attach_type_str (at)));
  RET (octave_value (m));
}

HANDLER (h_attach_type_by_name)
{
  string name = arg_str (a, 0, "name");
  enum bpf_attach_type at;
  int r = libbpf_attach_type_by_name (name.c_str (), &at);
  if (r < 0)
    fail_errno ("attach_type_by_name", r);
  RET (intv (at));
}

HANDLER (h_find_vmlinux_btf_id)
{
  string name = arg_str (a, 0, "name");
  int r = libbpf_find_vmlinux_btf_id (name.c_str (), static_cast<enum bpf_attach_type> (0));
  if (r < 0)
    fail_errno ("find_vmlinux_btf_id", r);
  RET (intv (r));
}

HANDLER (h_handle_kind)
{
  uint64_t h = arg_u64 (a, 0, "handle");
  std::lock_guard<std::mutex> lock (g_mutex);
  auto it = g_registry.find (h);
  RET (strv (it == g_registry.end () ? "" : it->second.c_str ()));
}

HANDLER (h_set_memlock_rlim)
{
  long v = arg_long (a, 0, "bytes");
  int r = libbpf_set_memlock_rlim (static_cast<size_t> (v));
  if (r)
    fail_errno ("set_memlock_rlim", r);
  RET0 ();
}

// ===========================================================================
// bpf_object
// ===========================================================================

HANDLER (h_object_open_file)
{
  ensure_init ();
  string path = arg_str (a, 0, "path");
  Opts opts (a, 1);
  struct bpf_object_open_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  string oname = opts.str ("object_name");
  string pinroot = opts.str ("pin_root_path");
  string kconfig = opts.str ("kconfig");
  string btfpath = opts.str ("btf_custom_path");
  string tokenpath = opts.str ("bpf_token_path");
  if (! oname.empty ()) o.object_name = oname.c_str ();
  if (! pinroot.empty ()) o.pin_root_path = pinroot.c_str ();
  if (! kconfig.empty ()) o.kconfig = kconfig.c_str ();
  if (! btfpath.empty ()) o.btf_custom_path = btfpath.c_str ();
  if (! tokenpath.empty ()) o.bpf_token_path = tokenpath.c_str ();
  o.relaxed_maps = opts.flag ("relaxed_maps", false);
  o.kernel_log_level = static_cast<__u32> (opts.num ("kernel_log_level", 0));
  string logbuf;
  if (opts.got ("kernel_log_size"))
    {
      size_t sz = static_cast<size_t> (opts.num ("kernel_log_size", 0));
      if (sz > 0)
        {
          logbuf.resize (sz, '\0');
          o.kernel_log_buf = &logbuf[0];
          o.kernel_log_size = sz;
        }
    }
  struct bpf_object *obj =
    static_cast<struct bpf_object *> (PTR_CHECK (bpf_object__open_file (path.c_str (), &o),
                                                 "object_open_file(" + path + ")"));
  reg_add (obj, "object");
  if (nargout > 1)
    {
      octave_value_list rv (2);
      rv(0) = u64v (reinterpret_cast<uint64_t> (obj));
      rv(1) = octave_value (logbuf);
      return rv;
    }
  RET (u64v (reinterpret_cast<uint64_t> (obj)));
}

HANDLER (h_object_open_mem)
{
  ensure_init ();
  string data = arg_bytes (a, 0, "data");
  string name = opt_str (a, 1, "");
  Opts opts (a, 2);
  if (data.empty ())
    fail ("object_open_mem: empty ELF image");

  // libbpf keeps a pointer to this buffer (elf_memory) until the object is
  // closed, so the wrapper owns the copy and frees it in object_close.
  void *buf = std::malloc (data.size ());
  if (! buf)
    fail ("object_open_mem: out of memory");
  std::memcpy (buf, data.data (), data.size ());

  struct bpf_object_open_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  string pinroot = opts.str ("pin_root_path");
  if (! pinroot.empty ()) o.pin_root_path = pinroot.c_str ();
  string kconfig = opts.str ("kconfig");
  if (! kconfig.empty ()) o.kconfig = kconfig.c_str ();
  string btfpath = opts.str ("btf_custom_path");
  if (! btfpath.empty ()) o.btf_custom_path = btfpath.c_str ();
  o.relaxed_maps = opts.flag ("relaxed_maps", false);
  o.kernel_log_level = static_cast<__u32> (opts.num ("kernel_log_level", 0));
  o.object_name = name.empty () ? nullptr : name.c_str ();

  struct bpf_object *obj =
    static_cast<struct bpf_object *> (bpf_object__open_mem (buf, data.size (), &o));
  long err = libbpf_get_error (obj);
  if (err)
    {
      std::free (buf);
      fail_errno ("object_open_mem", err);
    }
  reg_add (obj, "object");
  {
    std::lock_guard<std::mutex> lock (g_mutex);
    g_owned_buffers[reinterpret_cast<uint64_t> (obj)] = buf;
  }
  RET (u64v (reinterpret_cast<uint64_t> (obj)));
}

HANDLER (h_object_load)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  INT_CHECK (bpf_object__load (obj), "object_load");
  RET0 ();
}

HANDLER (h_object_prepare)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  INT_CHECK (bpf_object__prepare (obj), "object_prepare");
  RET0 ();
}

HANDLER (h_object_close)
{
  uint64_t h = arg_u64 (a, 0, "obj");
  if (! h)
    RET0 ();
  struct bpf_object *obj = reinterpret_cast<struct bpf_object *> (h);
  // Free any per program log buffers before the object goes away.
  {
    std::lock_guard<std::mutex> lock (g_mutex);
    for (auto it = g_log_buffers.begin (); it != g_log_buffers.end (); )
      it = g_log_buffers.erase (it);
  }
  bpf_object__close (obj);
  reg_del (obj);
  RET0 ();
}

HANDLER (h_object_name)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  RET (strv (bpf_object__name (obj)));
}

HANDLER (h_object_kversion)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  RET (intv (bpf_object__kversion (obj)));
}

HANDLER (h_object_set_kversion)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  INT_CHECK (bpf_object__set_kversion (obj, static_cast<__u32> (arg_long (a, 1, "kver"))),
             "object_set_kversion");
  RET0 ();
}

HANDLER (h_object_btf_fd)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  RET (intv (bpf_object__btf_fd (obj)));
}

HANDLER (h_object_btf)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  struct btf *btf = bpf_object__btf (obj);
  reg_add (btf, "btf_borrowed");
  RET (u64v (reinterpret_cast<uint64_t> (btf)));
}

HANDLER (h_object_token_fd)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  RET (intv (bpf_object__token_fd (obj)));
}

HANDLER (h_object_find_program)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string name = arg_str (a, 1, "name");
  struct bpf_program *p = bpf_object__find_program_by_name (obj, name.c_str ());
  reg_add (p, "program_borrowed");
  RET (u64v (reinterpret_cast<uint64_t> (p)));
}

HANDLER (h_object_find_map)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string name = arg_str (a, 1, "name");
  struct bpf_map *m = bpf_object__find_map_by_name (obj, name.c_str ());
  reg_add (m, "map_borrowed");
  RET (u64v (reinterpret_cast<uint64_t> (m)));
}

HANDLER (h_object_find_map_fd)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string name = arg_str (a, 1, "name");
  RET (intv (bpf_object__find_map_fd_by_name (obj, name.c_str ())));
}

HANDLER (h_object_programs)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  std::vector<string> names;
  struct bpf_program *p = nullptr;
  while ((p = bpf_object__next_program (obj, p)) != nullptr)
    names.push_back (bpf_program__name (p));
  Cell c (dim_vector (1, static_cast<octave_idx_type> (names.size ())));
  for (size_t i = 0; i < names.size (); i++)
    c(static_cast<octave_idx_type> (i)) = octave_value (names[i]);
  RET (octave_value (c));
}

HANDLER (h_object_maps)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  std::vector<string> names;
  struct bpf_map *m = nullptr;
  while ((m = bpf_object__next_map (obj, m)) != nullptr)
    names.push_back (bpf_map__name (m));
  Cell c (dim_vector (1, static_cast<octave_idx_type> (names.size ())));
  for (size_t i = 0; i < names.size (); i++)
    c(static_cast<octave_idx_type> (i)) = octave_value (names[i]);
  RET (octave_value (c));
}

HANDLER (h_object_pin)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_object__pin (obj, path.c_str ()), "object_pin");
  RET0 ();
}

HANDLER (h_object_unpin)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_object__unpin (obj, path.c_str ()), "object_unpin");
  RET0 ();
}

HANDLER (h_object_pin_maps)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_object__pin_maps (obj, path.c_str ()), "object_pin_maps");
  RET0 ();
}

HANDLER (h_object_unpin_maps)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string path = opt_str (a, 1, "");
  INT_CHECK (bpf_object__unpin_maps (obj, path.empty () ? nullptr : path.c_str ()),
             "object_unpin_maps");
  RET0 ();
}

HANDLER (h_object_pin_programs)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_object__pin_programs (obj, path.c_str ()), "object_pin_programs");
  RET0 ();
}

HANDLER (h_object_unpin_programs)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  string path = opt_str (a, 1, "");
  INT_CHECK (bpf_object__unpin_programs (obj, path.empty () ? nullptr : path.c_str ()),
             "object_unpin_programs");
  RET0 ();
}

HANDLER (h_object_set_log)
{
  struct bpf_object *obj =
    checked<struct bpf_object> (arg_u64 (a, 0, "obj"), "object");
  size_t sz = static_cast<size_t> (opt_long (a, 1, 1024 * 1024));
  struct bpf_program *p = nullptr;
  while ((p = bpf_object__next_program (obj, p)) != nullptr)
    {
      string &buf = g_log_buffers[reinterpret_cast<uint64_t> (p)];
      buf.assign (sz, '\0');
      bpf_program__set_log_buf (p, &buf[0], sz);
    }
  RET0 ();
}

// ===========================================================================
// bpf_program
// ===========================================================================

HANDLER (h_program_fd)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (intv (bpf_program__fd (p)));
}

HANDLER (h_program_name)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (strv (bpf_program__name (p)));
}

HANDLER (h_program_section_name)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (strv (bpf_program__section_name (p)));
}

HANDLER (h_program_type)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  enum bpf_prog_type t = bpf_program__type (p);
  octave_scalar_map m;
  m.assign ("value", octave_value (static_cast<double> (t)));
  m.assign ("name", strv (libbpf_bpf_prog_type_str (t)));
  RET (octave_value (m));
}

HANDLER (h_program_set_type)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  INT_CHECK (bpf_program__set_type (p, static_cast<enum bpf_prog_type> (arg_long (a, 1, "type"))),
             "program_set_type");
  RET0 ();
}

HANDLER (h_program_expected_attach_type)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  enum bpf_attach_type t = bpf_program__expected_attach_type (p);
  octave_scalar_map m;
  m.assign ("value", octave_value (static_cast<double> (t)));
  m.assign ("name", strv (libbpf_bpf_attach_type_str (t)));
  RET (octave_value (m));
}

HANDLER (h_program_set_expected_attach_type)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  INT_CHECK (bpf_program__set_expected_attach_type (
               p, static_cast<enum bpf_attach_type> (arg_long (a, 1, "type"))),
             "program_set_expected_attach_type");
  RET0 ();
}

HANDLER (h_program_autoload)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (octave_value (bpf_program__autoload (p)));
}

HANDLER (h_program_set_autoload)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  INT_CHECK (bpf_program__set_autoload (p, opt_bool (a, 1, true)), "program_set_autoload");
  RET0 ();
}

HANDLER (h_program_autoattach)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (octave_value (bpf_program__autoattach (p)));
}

HANDLER (h_program_set_autoattach)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  bpf_program__set_autoattach (p, opt_bool (a, 1, true));
  RET0 ();
}

HANDLER (h_program_insns)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  const struct bpf_insn *insns = bpf_program__insns (p);
  size_t cnt = bpf_program__insn_cnt (p);
  RET (bytes_value (insns, cnt * sizeof (struct bpf_insn)));
}

HANDLER (h_program_insn_cnt)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (intv (static_cast<long> (bpf_program__insn_cnt (p))));
}

HANDLER (h_program_set_insns)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string bytes = arg_bytes (a, 1, "insns");
  if (bytes.size () % sizeof (struct bpf_insn) != 0)
    fail ("program_set_insns: instruction buffer size must be a multiple of 8");
  size_t cnt = bytes.size () / sizeof (struct bpf_insn);
  std::vector<struct bpf_insn> insns (cnt);
  if (cnt)
    std::memcpy (insns.data (), bytes.data (), bytes.size ());
  INT_CHECK (bpf_program__set_insns (p, insns.data (), cnt), "program_set_insns");
  RET0 ();
}

HANDLER (h_program_log_level)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (intv (bpf_program__log_level (p)));
}

HANDLER (h_program_set_log_level)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  INT_CHECK (bpf_program__set_log_level (p, static_cast<__u32> (arg_long (a, 1, "level"))),
             "program_set_log_level");
  RET0 ();
}

HANDLER (h_program_set_log_buf)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  size_t sz = static_cast<size_t> (opt_long (a, 1, 1024 * 1024));
  string &buf = g_log_buffers[reinterpret_cast<uint64_t> (p)];
  buf.assign (sz, '\0');
  INT_CHECK (bpf_program__set_log_buf (p, &buf[0], sz), "program_set_log_buf");
  RET0 ();
}

HANDLER (h_program_get_log)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  auto it = g_log_buffers.find (reinterpret_cast<uint64_t> (p));
  if (it == g_log_buffers.end ())
    RET (octave_value (string ()));
  RET (octave_value (string (it->second.c_str ())));
}

HANDLER (h_program_set_attach_target)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  long id = arg_long (a, 1, "attach_btf_id");
  string fname = opt_str (a, 2, "");
  INT_CHECK (bpf_program__set_attach_target (p, static_cast<int> (id),
                                             fname.empty () ? nullptr : fname.c_str ()),
             "program_set_attach_target");
  RET0 ();
}

HANDLER (h_program_set_flags)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  INT_CHECK (bpf_program__set_flags (p, static_cast<__u32> (arg_long (a, 1, "flags"))),
             "program_set_flags");
  RET0 ();
}

HANDLER (h_program_flags)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  RET (intv (bpf_program__flags (p)));
}

HANDLER (h_program_pin)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_program__pin (p, path.c_str ()), "program_pin");
  RET0 ();
}

HANDLER (h_program_unpin)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_program__unpin (p, path.c_str ()), "program_unpin");
  RET0 ();
}

HANDLER (h_program_unload)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  bpf_program__unload (p);
  RET0 ();
}

HANDLER (h_program_set_ifindex)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  bpf_program__set_ifindex (p, static_cast<__u32> (arg_long (a, 1, "ifindex")));
  RET0 ();
}

// ---------------------------------------------------------------- attach ---

HANDLER (h_program_attach)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  struct bpf_link *l =
    static_cast<struct bpf_link *> (PTR_CHECK (bpf_program__attach (p), "program_attach"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_kprobe)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string func = arg_str (a, 1, "func_name");
  Opts opts (a, 2);
  struct bpf_kprobe_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.retprobe = opts.flag ("retprobe", false);
  o.bpf_cookie = static_cast<__u64> (opts.num ("bpf_cookie", 0));
  if (opts.got ("offset")) o.offset = static_cast<size_t> (opts.num ("offset", 0));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_kprobe_opts (p, func.c_str (), &o),
               "attach_kprobe(" + func + ")"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_kprobe_multi)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string pattern = opt_str (a, 1, "");
  Opts opts (a, 2);
  struct bpf_kprobe_multi_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.retprobe = opts.flag ("retprobe", false);
  o.session = opts.flag ("session", false);
  o.unique_match = opts.flag ("unique_match", false);
  std::vector<string> syms;
  std::vector<const char *> syms_c;
  if (opts.got ("syms"))
    {
      Cell c = opts.cell ("syms");
      for (octave_idx_type i = 0; i < c.numel (); i++)
        syms.push_back (c(i).string_value ());
      for (auto &s : syms)
        syms_c.push_back (s.c_str ());
      o.syms = syms_c.data ();
      o.cnt = syms_c.size ();
    }
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_kprobe_multi_opts (
                 p, pattern.empty () ? nullptr : pattern.c_str (), &o),
               "attach_kprobe_multi"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_uprobe)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  long pid = arg_long (a, 1, "pid");
  string path = arg_str (a, 2, "binary_path");
  size_t off = static_cast<size_t> (opt_long (a, 3, 0));
  Opts opts (a, 4);
  struct bpf_uprobe_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.retprobe = opts.flag ("retprobe", false);
  o.bpf_cookie = static_cast<__u64> (opts.num ("bpf_cookie", 0));
  string fname = opts.str ("func_name");
  if (! fname.empty ()) o.func_name = fname.c_str ();
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_uprobe_opts (p, static_cast<pid_t> (pid), path.c_str (),
                                                off, &o),
               "attach_uprobe(" + path + ")"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_uprobe_multi)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  long pid = arg_long (a, 1, "pid");
  string path = arg_str (a, 2, "binary_path");
  string pattern = opt_str (a, 3, "");
  Opts opts (a, 4);
  struct bpf_uprobe_multi_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.retprobe = opts.flag ("retprobe", false);
  o.session = opts.flag ("session", false);
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_uprobe_multi (
                 p, static_cast<pid_t> (pid), path.c_str (),
                 pattern.empty () ? nullptr : pattern.c_str (), &o),
               "attach_uprobe_multi"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_tracepoint)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string cat = arg_str (a, 1, "category");
  string nm = arg_str (a, 2, "name");
  Opts opts (a, 3);
  struct bpf_tracepoint_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.bpf_cookie = static_cast<__u64> (opts.num ("bpf_cookie", 0));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_tracepoint_opts (p, cat.c_str (), nm.c_str (), &o),
               "attach_tracepoint(" + cat + ":" + nm + ")"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_raw_tracepoint)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string nm = arg_str (a, 1, "name");
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_raw_tracepoint (p, nm.c_str ()),
               "attach_raw_tracepoint(" + nm + ")"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_trace)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  struct bpf_trace_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_trace_opts (p, &o), "attach_trace"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_lsm)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_lsm (p), "attach_lsm"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_cgroup)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int fd = static_cast<int> (arg_long (a, 1, "cgroup_fd"));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_cgroup (p, fd), "attach_cgroup"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_netns)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int fd = static_cast<int> (arg_long (a, 1, "netns_fd"));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_netns (p, fd), "attach_netns"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_xdp)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int ifindex = static_cast<int> (arg_long (a, 1, "ifindex"));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_xdp (p, ifindex), "attach_xdp"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_sockmap)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int fd = static_cast<int> (arg_long (a, 1, "map_fd"));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_sockmap (p, fd), "attach_sockmap"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_freplace)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int fd = static_cast<int> (arg_long (a, 1, "target_fd"));
  string fname = opt_str (a, 2, "");
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_freplace (p, fd, fname.empty () ? nullptr : fname.c_str ()),
               "attach_freplace"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_netfilter)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  Opts opts (a, 1);
  struct bpf_netfilter_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.pf = static_cast<__u32> (opts.num ("pf", 2));
  o.hooknum = static_cast<__u32> (opts.num ("hooknum", 0));
  o.priority = static_cast<__s32> (opts.num ("priority", 0));
  o.flags = static_cast<__u32> (opts.num ("flags", 0));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_netfilter (p, &o), "attach_netfilter"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_tcx)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int ifindex = static_cast<int> (arg_long (a, 1, "ifindex"));
  Opts opts (a, 2);
  struct bpf_tcx_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.flags = static_cast<__u32> (opts.num ("flags", 0));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_tcx (p, ifindex, &o), "attach_tcx"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_netkit)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int ifindex = static_cast<int> (arg_long (a, 1, "ifindex"));
  Opts opts (a, 2);
  struct bpf_netkit_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.flags = static_cast<__u32> (opts.num ("flags", 0));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_netkit (p, ifindex, &o), "attach_netkit"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_iter)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  struct bpf_iter_attach_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_iter (p, &o), "attach_iter"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_usdt)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  long pid = arg_long (a, 1, "pid");
  string path = arg_str (a, 2, "binary_path");
  string provider = arg_str (a, 3, "provider");
  string name = arg_str (a, 4, "name");
  Opts opts (a, 5);
  struct bpf_usdt_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.usdt_cookie = static_cast<__u64> (opts.num ("usdt_cookie", 0));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_usdt (p, static_cast<pid_t> (pid), path.c_str (),
                                         provider.c_str (), name.c_str (), &o),
               "attach_usdt"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

// ---------------------------------------------------------------------------
// Compile-time feature probes.
//
// This wrapper is built against whatever libbpf happens to be installed on the
// build host.  Some struct fields / entry points only exist in newer or custom
// libbpf builds -- e.g. bpf_perf_event_opts.dont_enable was added in libbpf
// 1.5, and bpf_program__attach_tracing_multi() together with struct
// bpf_tracing_multi_opts are provided by the custom tracing-multi libbpf used
// by this project.  Rather than failing to compile on older distro packages
// (Ubuntu's apt libbpf-dev, for instance), we probe the headers we are actually
// compiled against and degrade those features gracefully.  The corresponding
// entry points are already declared weak elsewhere, so the runtime probe in
// each handler still reports "not available" when the shared object lacks them.
// ---------------------------------------------------------------------------

// Does struct bpf_perf_event_opts contain the dont_enable field?
template <typename T>
auto libbpf_has_perf_dont_enable (int)
  -> decltype (static_cast<void> (static_cast<T *> (nullptr)->dont_enable),
               std::true_type {});
template <typename T>
auto libbpf_has_perf_dont_enable (...)
  -> std::false_type;

// Is struct bpf_tracing_multi_opts a complete type (custom tracing-multi
// libbpf)?  When it is only forward-declared (or absent entirely) sizeof fails
// and we fall back to the false overload.
template <typename T>
auto libbpf_tracing_multi_complete (int)
  -> decltype (static_cast<void> (sizeof (T)), std::true_type {});
template <typename T>
auto libbpf_tracing_multi_complete (...)
  -> std::false_type;

using perf_dont_enable_available =
  decltype (libbpf_has_perf_dont_enable<struct bpf_perf_event_opts> (0));
using tracing_multi_available =
  decltype (libbpf_tracing_multi_complete<struct bpf_tracing_multi_opts> (0));

// Set bpf_perf_event_opts.dont_enable only when the field exists in the headers
// we were compiled against (libbpf >= 1.5).  The actual field access lives in a
// template whose type parameter T is the opts struct, which makes the body
// dependent and defers its compilation; the overload is only ever instantiated
// for the std::true_type tag (i.e. when the probe below says the field exists),
// so building against an older libbpf that lacks it is fine.
inline void
set_perf_dont_enable (struct bpf_perf_event_opts&, bool, std::false_type) { }

template <typename T = struct bpf_perf_event_opts>
inline void
set_perf_dont_enable (T& o, bool v, std::true_type)
{
  o.dont_enable = v;
}

// Perform the tracing-multi attach.  The struct type is carried as a template
// parameter so the body that names struct bpf_tracing_multi_opts is dependent
// and only compiled when this overload is actually instantiated -- which only
// happens for the std::true_type tag (set when the struct is a complete type).
// Against a stock libbpf that lacks it, the std::false_type overload is chosen
// and returns nullptr; the handler then reports the feature as unavailable.
inline struct bpf_link *
do_attach_tracing_multi (struct bpf_program *, const char *, std::false_type)
{
  return nullptr;
}

template <typename T = struct bpf_tracing_multi_opts>
inline struct bpf_link *
do_attach_tracing_multi (struct bpf_program *p, const char *pattern,
                         std::true_type)
{
  T o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  return static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_tracing_multi (p, pattern, &o),
               "attach_tracing_multi"));
}

HANDLER (h_program_attach_perf_event)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  int pfd = static_cast<int> (arg_long (a, 1, "perf_fd"));
  Opts opts (a, 2);
  struct bpf_perf_event_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.bpf_cookie = static_cast<__u64> (opts.num ("bpf_cookie", 0));
  o.force_ioctl_attach = opts.flag ("force_ioctl_attach", false);
  set_perf_dont_enable (
      o, opts.flag ("dont_enable", false), perf_dont_enable_available {});
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_perf_event_opts (p, pfd, &o), "attach_perf_event"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_ksyscall)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string name = arg_str (a, 1, "syscall");
  Opts opts (a, 2);
  struct bpf_ksyscall_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.retprobe = opts.flag ("retprobe", false);
  o.bpf_cookie = static_cast<__u64> (opts.num ("bpf_cookie", 0));
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_program__attach_ksyscall (p, name.c_str (), &o),
               "attach_ksyscall(" + name + ")"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_attach_tracing_multi)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string pattern = opt_str (a, 1, "");
  if (! bpf_program__attach_tracing_multi)
    fail ("attach_tracing_multi is not available in this libbpf version");
  struct bpf_link *l = do_attach_tracing_multi (
      p, pattern.empty () ? nullptr : pattern.c_str (),
      tracing_multi_available {});
  if (! l)
    fail ("attach_tracing_multi failed (tracing-multi support may be missing)");
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

HANDLER (h_program_test_run)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string data = has (a, 1) && ! a(1).isempty () ? arg_bytes (a, 1, "data") : string ();
  long repeat = opt_long (a, 2, 1);
  Opts opts (a, 3);

  struct bpf_test_run_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.repeat = static_cast<int> (repeat);
  o.data_in = data.empty () ? nullptr : const_cast<void *> (static_cast<const void *> (data.data ()));
  o.data_size_in = static_cast<__u32> (data.size ());

  size_t outsz = static_cast<size_t> (opts.num ("data_size_out", 4096));
  if (outsz == 0)
    outsz = 4096;
  std::vector<char> out (outsz);
  o.data_out = out.data ();
  o.data_size_out = static_cast<__u32> (outsz);

  // ctx_out must be left alone unless the caller asks for it: at least the
  // socket filter test run path returns -ENOSPC when a context buffer is
  // supplied for a program type that has no context to report.
  std::vector<char> ctxout;
  size_t ctxsz = 0;
  if (opts.got ("ctx_size_out"))
    {
      ctxsz = static_cast<size_t> (opts.num ("ctx_size_out", 0));
      if (ctxsz == 0)
        ctxsz = 1;
      ctxout.resize (ctxsz);
      o.ctx_out = ctxout.data ();
      o.ctx_size_out = static_cast<__u32> (ctxsz);
    }
  else
    {
      o.ctx_out = nullptr;
      o.ctx_size_out = 0;
    }
  o.ctx_in = nullptr;
  o.ctx_size_in = 0;

  INT_CHECK (bpf_prog_test_run_opts (bpf_program__fd (p), &o), "program_test_run");

  octave_scalar_map m;
  m.assign ("retval", octave_value (static_cast<double> (o.retval)));
  m.assign ("duration_ns", octave_value (static_cast<double> (o.duration)));
  m.assign ("data_size_out", octave_value (static_cast<double> (o.data_size_out)));
  m.assign ("ctx_size_out", octave_value (static_cast<double> (o.ctx_size_out)));
  m.assign ("data_out", bytes_value (out.data (), o.data_size_out));
  m.assign ("ctx_out", bytes_value (ctxout.empty () ? nullptr : ctxout.data (),
                                    o.ctx_size_out));
  RET (octave_value (m));
}

// ===========================================================================
// bpf_link
// ===========================================================================

HANDLER (h_link_fd)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  RET (intv (bpf_link__fd (l)));
}

HANDLER (h_link_destroy)
{
  uint64_t h = arg_u64 (a, 0, "link");
  if (! h)
    RET0 ();
  struct bpf_link *l = reinterpret_cast<struct bpf_link *> (h);
  INT_CHECK (bpf_link__destroy (l), "link_destroy");
  reg_del (l);
  RET0 ();
}

HANDLER (h_link_detach)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  INT_CHECK (bpf_link__detach (l), "link_detach");
  RET0 ();
}

HANDLER (h_link_disconnect)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  bpf_link__disconnect (l);
  RET0 ();
}

HANDLER (h_link_pin)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_link__pin (l, path.c_str ()), "link_pin");
  RET0 ();
}

HANDLER (h_link_unpin)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  INT_CHECK (bpf_link__unpin (l), "link_unpin");
  RET0 ();
}

HANDLER (h_link_pin_path)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  RET (strv (bpf_link__pin_path (l)));
}

HANDLER (h_link_update_program)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 1, "prog"), "program");
  INT_CHECK (bpf_link__update_program (l, p), "link_update_program");
  RET0 ();
}

HANDLER (h_link_update_map)
{
  struct bpf_link *l = checked<struct bpf_link> (arg_u64 (a, 0, "link"), "link");
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 1, "map"), "map");
  INT_CHECK (bpf_link__update_map (l, m), "link_update_map");
  RET0 ();
}

HANDLER (h_link_open)
{
  string path = arg_str (a, 0, "path");
  struct bpf_link *l = static_cast<struct bpf_link *> (
    PTR_CHECK (bpf_link__open (path.c_str ()), "link_open(" + path + ")"));
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

// ===========================================================================
// bpf_map
// ===========================================================================

HANDLER (h_map_fd)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (intv (bpf_map__fd (m)));
}

HANDLER (h_map_name)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (strv (bpf_map__name (m)));
}

HANDLER (h_map_type)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  enum bpf_map_type t = bpf_map__type (m);
  octave_scalar_map s;
  s.assign ("value", octave_value (static_cast<double> (t)));
  s.assign ("name", strv (libbpf_bpf_map_type_str (t)));
  RET (octave_value (s));
}

HANDLER (h_map_set_type)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  INT_CHECK (bpf_map__set_type (m, static_cast<enum bpf_map_type> (arg_long (a, 1, "type"))),
             "map_set_type");
  RET0 ();
}

HANDLER (h_map_key_size)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (intv (bpf_map__key_size (m)));
}

HANDLER (h_map_value_size)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (intv (bpf_map__value_size (m)));
}

HANDLER (h_map_max_entries)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (intv (bpf_map__max_entries (m)));
}

HANDLER (h_map_map_flags)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (intv (bpf_map__map_flags (m)));
}

HANDLER (h_map_set_max_entries)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  INT_CHECK (bpf_map__set_max_entries (m, static_cast<__u32> (arg_long (a, 1, "max_entries"))),
             "map_set_max_entries");
  RET0 ();
}

HANDLER (h_map_set_map_flags)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  INT_CHECK (bpf_map__set_map_flags (m, static_cast<__u32> (arg_long (a, 1, "flags"))),
             "map_set_map_flags");
  RET0 ();
}

HANDLER (h_map_set_key_size)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  INT_CHECK (bpf_map__set_key_size (m, static_cast<__u32> (arg_long (a, 1, "size"))),
             "map_set_key_size");
  RET0 ();
}

HANDLER (h_map_set_value_size)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  INT_CHECK (bpf_map__set_value_size (m, static_cast<__u32> (arg_long (a, 1, "size"))),
             "map_set_value_size");
  RET0 ();
}

HANDLER (h_map_btf_key_type_id)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (intv (bpf_map__btf_key_type_id (m)));
}

HANDLER (h_map_btf_value_type_id)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (intv (bpf_map__btf_value_type_id (m)));
}

HANDLER (h_map_is_internal)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (octave_value (bpf_map__is_internal (m)));
}

HANDLER (h_map_reuse_fd)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  INT_CHECK (bpf_map__reuse_fd (m, static_cast<int> (arg_long (a, 1, "fd"))), "map_reuse_fd");
  RET0 ();
}

HANDLER (h_map_set_inner_map_fd)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  INT_CHECK (bpf_map__set_inner_map_fd (m, static_cast<int> (arg_long (a, 1, "fd"))),
             "map_set_inner_map_fd");
  RET0 ();
}

HANDLER (h_map_inner_map)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  struct bpf_map *inner = bpf_map__inner_map (m);
  reg_add (inner, "map_borrowed");
  RET (u64v (reinterpret_cast<uint64_t> (inner)));
}

HANDLER (h_map_pin)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  string path = opt_str (a, 1, "");
  INT_CHECK (bpf_map__pin (m, path.empty () ? nullptr : path.c_str ()), "map_pin");
  RET0 ();
}

HANDLER (h_map_unpin)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  string path = opt_str (a, 1, "");
  INT_CHECK (bpf_map__unpin (m, path.empty () ? nullptr : path.c_str ()), "map_unpin");
  RET0 ();
}

HANDLER (h_map_set_pin_path)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  string path = opt_str (a, 1, "");
  INT_CHECK (bpf_map__set_pin_path (m, path.empty () ? nullptr : path.c_str ()),
             "map_set_pin_path");
  RET0 ();
}

HANDLER (h_map_pin_path)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (strv (bpf_map__pin_path (m)));
}

HANDLER (h_map_is_pinned)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  RET (octave_value (bpf_map__is_pinned (m)));
}

HANDLER (h_map_lookup)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  string key = arg_bytes (a, 1, "key");
  long flags = opt_long (a, 2, 0);
  size_t vsz = static_cast<size_t> (bpf_map__value_size (m));
  std::vector<char> val (vsz ? vsz : 1);
  INT_CHECK (bpf_map__lookup_elem (m, key.data (), key.size (), val.data (), vsz,
                                   static_cast<__u64> (flags)),
             "map_lookup");
  RET (bytes_value (val.data (), vsz));
}

HANDLER (h_map_update)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  string key = arg_bytes (a, 1, "key");
  string val = arg_bytes (a, 2, "value");
  long flags = opt_long (a, 3, 0);
  INT_CHECK (bpf_map__update_elem (m, key.data (), key.size (), val.data (), val.size (),
                                   static_cast<__u64> (flags)),
             "map_update");
  RET0 ();
}

HANDLER (h_map_delete)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  string key = arg_bytes (a, 1, "key");
  long flags = opt_long (a, 2, 0);
  INT_CHECK (bpf_map__delete_elem (m, key.data (), key.size (), static_cast<__u64> (flags)),
             "map_delete");
  RET0 ();
}

HANDLER (h_map_lookup_and_delete)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  string key = arg_bytes (a, 1, "key");
  long flags = opt_long (a, 2, 0);
  size_t vsz = static_cast<size_t> (bpf_map__value_size (m));
  std::vector<char> val (vsz ? vsz : 1);
  INT_CHECK (bpf_map__lookup_and_delete_elem (m, key.data (), key.size (), val.data (), vsz,
                                              static_cast<__u64> (flags)),
             "map_lookup_and_delete");
  RET (bytes_value (val.data (), vsz));
}

HANDLER (h_map_get_next_key)
{
  struct bpf_map *m = checked<struct bpf_map> (arg_u64 (a, 0, "map"), "map");
  size_t ksz = static_cast<size_t> (bpf_map__key_size (m));
  bool have_key = has (a, 1) && ! a(1).isempty ();
  string key = have_key ? arg_bytes (a, 1, "key") : string ();
  std::vector<char> next (ksz ? ksz : 1);
  int r = bpf_map__get_next_key (m, have_key ? key.data () : nullptr, next.data (), ksz);
  if (r < 0)
    {
      if (r == -ENOENT)
        RET (octave_value (Matrix (0, 0)));
      fail_errno ("map_get_next_key", r);
    }
  RET (bytes_value (next.data (), ksz));
}

// ------------------------------------------------- map element api by fd ---

HANDLER (h_map_lookup_fd)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  string key = arg_bytes (a, 1, "key");
  long vsz = opt_long (a, 2, 0);
  if (vsz <= 0)
    fail ("map_lookup_fd: value size must be given as the third argument");
  std::vector<char> val (static_cast<size_t> (vsz));
  INT_CHECK (bpf_map_lookup_elem (fd, key.data (), val.data ()), "map_lookup_fd");
  RET (bytes_value (val.data (), static_cast<size_t> (vsz)));
}

HANDLER (h_map_update_fd)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  string key = arg_bytes (a, 1, "key");
  string val = arg_bytes (a, 2, "value");
  long flags = opt_long (a, 3, 0);
  INT_CHECK (bpf_map_update_elem (fd, key.data (), val.data (), static_cast<__u64> (flags)),
             "map_update_fd");
  RET0 ();
}

HANDLER (h_map_delete_fd)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  string key = arg_bytes (a, 1, "key");
  INT_CHECK (bpf_map_delete_elem (fd, key.data ()), "map_delete_fd");
  RET0 ();
}

HANDLER (h_map_next_key_fd)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  string key = arg_bytes (a, 1, "key");
  long ksz = arg_long (a, 2, "key_size");
  std::vector<char> next (static_cast<size_t> (ksz));
  int r = bpf_map_get_next_key (fd, key.data (), next.data ());
  if (r < 0)
    {
      if (r == -ENOENT)
        RET (octave_value (Matrix (0, 0)));
      fail_errno ("map_next_key_fd", r);
    }
  RET (bytes_value (next.data (), static_cast<size_t> (ksz)));
}

HANDLER (h_map_create)
{
  ensure_init ();
  long type = arg_long (a, 0, "map_type");
  string name = opt_str (a, 1, "");
  long ksz = arg_long (a, 2, "key_size");
  long vsz = arg_long (a, 3, "value_size");
  long maxent = arg_long (a, 4, "max_entries");
  Opts opts (a, 5);
  struct bpf_map_create_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.btf_fd = static_cast<__u32> (opts.num ("btf_fd", 0));
  o.btf_key_type_id = static_cast<__u32> (opts.num ("btf_key_type_id", 0));
  o.btf_value_type_id = static_cast<__u32> (opts.num ("btf_value_type_id", 0));
  o.inner_map_fd = static_cast<__u32> (opts.num ("inner_map_fd", 0));
  o.map_flags = static_cast<__u32> (opts.num ("map_flags", 0));
  o.map_extra = static_cast<__u64> (opts.num ("map_extra", 0));
  o.numa_node = static_cast<__u32> (opts.num ("numa_node", 0));
  o.map_ifindex = static_cast<__u32> (opts.num ("map_ifindex", 0));
  int fd = bpf_map_create (static_cast<enum bpf_map_type> (type),
                           name.empty () ? nullptr : name.c_str (),
                           static_cast<__u32> (ksz), static_cast<__u32> (vsz),
                           static_cast<__u32> (maxent), &o);
  INT_CHECK (fd, "map_create");
  RET (intv (fd));
}

HANDLER (h_close_fd)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  if (fd >= 0)
    ::close (fd);
  RET0 ();
}

HANDLER (h_map_freeze)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  INT_CHECK (bpf_map_freeze (fd), "map_freeze");
  RET0 ();
}

HANDLER (h_map_get_fd_by_id)
{
  long id = arg_long (a, 0, "id");
  int fd = bpf_map_get_fd_by_id (static_cast<__u32> (id));
  INT_CHECK (fd, "map_get_fd_by_id");
  RET (intv (fd));
}

HANDLER (h_map_get_next_id)
{
  long id = opt_long (a, 0, 0);
  __u32 nid = 0;
  INT_CHECK (bpf_map_get_next_id (static_cast<__u32> (id), &nid), "map_get_next_id");
  RET (intv (nid));
}

HANDLER (h_map_get_info)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  struct bpf_map_info info;
  std::memset (&info, 0, sizeof (info));
  __u32 len = sizeof (info);
  INT_CHECK (bpf_map_get_info_by_fd (fd, &info, &len), "map_get_info");
  octave_scalar_map m;
  m.assign ("type", octave_value (static_cast<double> (info.type)));
  m.assign ("id", octave_value (static_cast<double> (info.id)));
  m.assign ("key_size", octave_value (static_cast<double> (info.key_size)));
  m.assign ("value_size", octave_value (static_cast<double> (info.value_size)));
  m.assign ("max_entries", octave_value (static_cast<double> (info.max_entries)));
  m.assign ("map_flags", octave_value (static_cast<double> (info.map_flags)));
  m.assign ("name", octave_value (string (reinterpret_cast<const char *> (info.name))));
  m.assign ("ifindex", octave_value (static_cast<double> (info.ifindex)));
  m.assign ("btf_key_type_id", octave_value (static_cast<double> (info.btf_key_type_id)));
  m.assign ("btf_value_type_id", octave_value (static_cast<double> (info.btf_value_type_id)));
  m.assign ("btf_id", octave_value (static_cast<double> (info.btf_id)));
  RET (octave_value (m));
}

// ---------------------------------------------------------------- object ---

HANDLER (h_obj_get)
{
  string path = arg_str (a, 0, "path");
  int fd = bpf_obj_get (path.c_str ());
  INT_CHECK (fd, "obj_get(" + path + ")");
  RET (intv (fd));
}

HANDLER (h_obj_pin)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  string path = arg_str (a, 1, "path");
  INT_CHECK (bpf_obj_pin (fd, path.c_str ()), "obj_pin");
  RET0 ();
}

// ===========================================================================
// ring buffer / perf buffer
// ===========================================================================

namespace {

struct SampleSet
{
  std::vector<octave_value> samples;
  size_t max_samples = 0;
  bool overflow = false;
  size_t lost = 0;
};

void
finish_samples (SampleSet& ss, octave_value_list& rv)
{
  Cell c (dim_vector (1, static_cast<octave_idx_type> (ss.samples.size ())));
  for (size_t i = 0; i < ss.samples.size (); i++)
    c(static_cast<octave_idx_type> (i)) = ss.samples[i];
  rv(0) = octave_value (c);
  rv(1) = octave_value (static_cast<double> (ss.lost));
}

int
ringbuf_sample_cb (void *ctx, void *data, size_t size)
{
  SampleSet *ss = static_cast<SampleSet *> (ctx);
  try
    {
      ss->samples.push_back (bytes_value (data, size));
      if (ss->max_samples && ss->samples.size () >= ss->max_samples)
        return 1;   // ask libbpf to stop polling
    }
  catch (...)
    {
      return 1;
    }
  return 0;
}

void
perfbuf_sample_cb (void *ctx, int cpu, void *data, __u32 size)
{
  SampleSet *ss = static_cast<SampleSet *> (ctx);
  try
    {
      octave_scalar_map m;
      m.assign ("cpu", octave_value (static_cast<double> (cpu)));
      m.assign ("data", bytes_value (data, size));
      ss->samples.push_back (octave_value (m));
    }
  catch (...)
    {
      // Swallow: throwing through libbpf's C frames would be undefined.
    }
}

void
perfbuf_lost_cb (void *ctx, int cpu, __u64 cnt)
{
  SampleSet *ss = static_cast<SampleSet *> (ctx);
  (void) cpu;
  ss->lost += static_cast<size_t> (cnt);
}

}  // anonymous namespace

HANDLER (h_ringbuf_new)
{
  int fd = static_cast<int> (arg_long (a, 0, "map_fd"));
  struct ring_buffer_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  // Samples are collected by a C callback and returned to Octave after poll()
  // returns, so no interpreter call happens from inside libbpf.  The context
  // is owned by the caller (Octave) and stored alongside the ring buffer.
  SampleSet *ss = new SampleSet ();
  struct ring_buffer *rb = ring_buffer__new (fd, ringbuf_sample_cb, ss, &o);
  long err = libbpf_get_error (rb);
  if (err)
    {
      delete ss;
      fail_errno ("ringbuf_new", err);
    }
  reg_add (rb, "ringbuf");
  reg_add (ss, "ringbuf_ctx");
  octave_value_list rv (2);
  rv(0) = u64v (reinterpret_cast<uint64_t> (rb));
  rv(1) = u64v (reinterpret_cast<uint64_t> (ss));
  return rv;
}

HANDLER (h_ringbuf_add)
{
  struct ring_buffer *rb =
    checked<struct ring_buffer> (arg_u64 (a, 0, "rb"), "ring_buffer");
  int fd = static_cast<int> (arg_long (a, 1, "map_fd"));
  SampleSet *ss = reinterpret_cast<SampleSet *> (arg_u64 (a, 2, "ctx"));
  INT_CHECK (ring_buffer__add (rb, fd, ringbuf_sample_cb, ss), "ringbuf_add");
  RET0 ();
}

HANDLER (h_ringbuf_free)
{
  uint64_t h = arg_u64 (a, 0, "rb");
  if (! h)
    RET0 ();
  struct ring_buffer *rb = reinterpret_cast<struct ring_buffer *> (h);
  ring_buffer__free (rb);
  reg_del (rb);
  // The SampleSet that was passed as context is freed too; the m-code layer
  // passes it explicitly as the second argument.
  if (has (a, 1))
    {
      SampleSet *ss = reinterpret_cast<SampleSet *> (arg_u64 (a, 1, "ctx"));
      if (ss)
        {
          reg_del (ss);
          delete ss;
        }
    }
  RET0 ();
}

HANDLER (h_ringbuf_poll)
{
  struct ring_buffer *rb =
    checked<struct ring_buffer> (arg_u64 (a, 0, "rb"), "ring_buffer");
  SampleSet *ss = reinterpret_cast<SampleSet *> (arg_u64 (a, 1, "ctx"));
  long timeout = arg_long (a, 2, "timeout_ms");
  ss->max_samples = static_cast<size_t> (opt_long (a, 3, 0));
  ss->samples.clear ();
  ss->lost = 0;
  int r = ring_buffer__poll (rb, static_cast<int> (timeout));
  octave_value_list rv (2);
  if (r < 0)
    fail_errno ("ringbuf_poll", r);
  finish_samples (*ss, rv);
  return rv;
}

HANDLER (h_ringbuf_consume)
{
  struct ring_buffer *rb =
    checked<struct ring_buffer> (arg_u64 (a, 0, "rb"), "ring_buffer");
  SampleSet *ss = reinterpret_cast<SampleSet *> (arg_u64 (a, 1, "ctx"));
  ss->max_samples = static_cast<size_t> (opt_long (a, 2, 0));
  ss->samples.clear ();
  ss->lost = 0;
  int r = ring_buffer__consume (rb);
  octave_value_list rv (2);
  if (r < 0)
    fail_errno ("ringbuf_consume", r);
  finish_samples (*ss, rv);
  return rv;
}

HANDLER (h_ringbuf_epoll_fd)
{
  struct ring_buffer *rb =
    checked<struct ring_buffer> (arg_u64 (a, 0, "rb"), "ring_buffer");
  RET (intv (ring_buffer__epoll_fd (rb)));
}

HANDLER (h_perfbuf_new)
{
  int fd = static_cast<int> (arg_long (a, 0, "map_fd"));
  long page_cnt = opt_long (a, 1, 0);
  struct perf_buffer_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  SampleSet *ss = new SampleSet ();
  struct perf_buffer *pb = perf_buffer__new (fd, static_cast<size_t> (page_cnt),
                                             perfbuf_sample_cb, perfbuf_lost_cb, ss, &o);
  long err = libbpf_get_error (pb);
  if (err)
    {
      delete ss;
      fail_errno ("perfbuf_new", err);
    }
  reg_add (pb, "perfbuf");
  octave_value_list rv (2);
  rv(0) = u64v (reinterpret_cast<uint64_t> (pb));
  rv(1) = u64v (reinterpret_cast<uint64_t> (ss));
  return rv;
}

HANDLER (h_perfbuf_free)
{
  uint64_t h = arg_u64 (a, 0, "pb");
  if (! h)
    RET0 ();
  struct perf_buffer *pb = reinterpret_cast<struct perf_buffer *> (h);
  perf_buffer__free (pb);
  reg_del (pb);
  if (has (a, 1))
    {
      SampleSet *ss = reinterpret_cast<SampleSet *> (arg_u64 (a, 1, "ctx"));
      if (ss)
        {
          reg_del (ss);
          delete ss;
        }
    }
  RET0 ();
}

HANDLER (h_perfbuf_poll)
{
  struct perf_buffer *pb =
    checked<struct perf_buffer> (arg_u64 (a, 0, "pb"), "perf_buffer");
  SampleSet *ss = reinterpret_cast<SampleSet *> (arg_u64 (a, 1, "ctx"));
  long timeout = arg_long (a, 2, "timeout_ms");
  ss->max_samples = static_cast<size_t> (opt_long (a, 3, 0));
  ss->samples.clear ();
  ss->lost = 0;
  int r = perf_buffer__poll (pb, static_cast<int> (timeout));
  octave_value_list rv (2);
  if (r < 0)
    fail_errno ("perfbuf_poll", r);
  finish_samples (*ss, rv);
  return rv;
}

HANDLER (h_perfbuf_consume)
{
  struct perf_buffer *pb =
    checked<struct perf_buffer> (arg_u64 (a, 0, "pb"), "perf_buffer");
  SampleSet *ss = reinterpret_cast<SampleSet *> (arg_u64 (a, 1, "ctx"));
  ss->max_samples = 0;
  ss->samples.clear ();
  ss->lost = 0;
  int r = perf_buffer__consume (pb);
  octave_value_list rv (2);
  if (r < 0)
    fail_errno ("perfbuf_consume", r);
  finish_samples (*ss, rv);
  return rv;
}

HANDLER (h_perfbuf_buffer_cnt)
{
  struct perf_buffer *pb =
    checked<struct perf_buffer> (arg_u64 (a, 0, "pb"), "perf_buffer");
  RET (intv (static_cast<long> (perf_buffer__buffer_cnt (pb))));
}

HANDLER (h_perfbuf_epoll_fd)
{
  struct perf_buffer *pb =
    checked<struct perf_buffer> (arg_u64 (a, 0, "pb"), "perf_buffer");
  RET (intv (perf_buffer__epoll_fd (pb)));
}

// ===========================================================================
// BTF
// ===========================================================================

HANDLER (h_btf_parse_elf)
{
  string path = arg_str (a, 0, "path");
  struct btf_ext *ext = nullptr;
  struct btf *btf = btf__parse_elf (path.c_str (), &ext);
  long err = libbpf_get_error (btf);
  if (err)
    fail_errno ("btf_parse_elf(" + path + ")", err);
  reg_add (btf, "btf");
  octave_value_list rv (2);
  rv(0) = u64v (reinterpret_cast<uint64_t> (btf));
  rv(1) = u64v (reinterpret_cast<uint64_t> (ext));
  return rv;
}

HANDLER (h_btf_parse_raw)
{
  string data = arg_bytes (a, 0, "data");
  struct btf *btf = btf__new (reinterpret_cast<const __u8 *> (data.data ()), data.size ());
  long err = libbpf_get_error (btf);
  if (err)
    fail_errno ("btf_parse_raw", err);
  reg_add (btf, "btf");
  RET (u64v (reinterpret_cast<uint64_t> (btf)));
}

HANDLER (h_btf_new_empty)
{
  struct btf *btf = btf__new_empty ();
  long err = libbpf_get_error (btf);
  if (err)
    fail_errno ("btf_new_empty", err);
  reg_add (btf, "btf");
  RET (u64v (reinterpret_cast<uint64_t> (btf)));
}

HANDLER (h_btf_load_vmlinux)
{
  struct btf *btf = btf__load_vmlinux_btf ();
  long err = libbpf_get_error (btf);
  if (err)
    fail_errno ("btf_load_vmlinux", err);
  reg_add (btf, "btf");
  RET (u64v (reinterpret_cast<uint64_t> (btf)));
}

HANDLER (h_btf_load_from_kernel_by_id)
{
  long id = arg_long (a, 0, "btf_id");
  struct btf *btf = btf__load_from_kernel_by_id (static_cast<__u32> (id));
  long err = libbpf_get_error (btf);
  if (err)
    fail_errno ("btf_load_from_kernel_by_id", err);
  reg_add (btf, "btf");
  RET (u64v (reinterpret_cast<uint64_t> (btf)));
}

HANDLER (h_btf_load_into_kernel)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  int fd = btf__load_into_kernel (btf);
  INT_CHECK (fd, "btf_load_into_kernel");
  RET (intv (fd));
}

HANDLER (h_btf_free)
{
  uint64_t h = arg_u64 (a, 0, "btf");
  if (! h)
    RET0 ();
  struct btf *btf = reinterpret_cast<struct btf *> (h);
  btf__free (btf);
  reg_del (btf);
  RET0 ();
}

HANDLER (h_btf_fd)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  RET (intv (btf__fd (btf)));
}

HANDLER (h_btf_type_cnt)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  RET (intv (btf__type_cnt (btf)));
}

HANDLER (h_btf_find_by_name)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  string name = arg_str (a, 1, "name");
  RET (intv (btf__find_by_name (btf, name.c_str ())));
}

HANDLER (h_btf_find_by_name_kind)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  string name = arg_str (a, 1, "name");
  long kind = arg_long (a, 2, "kind");
  RET (intv (btf__find_by_name_kind (btf, name.c_str (), static_cast<__u32> (kind))));
}

HANDLER (h_btf_name_by_offset)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  long off = arg_long (a, 1, "offset");
  RET (strv (btf__name_by_offset (btf, static_cast<__u32> (off))));
}

HANDLER (h_btf_type_info)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  long id = arg_long (a, 1, "id");
  const struct btf_type *t = btf__type_by_id (btf, static_cast<__u32> (id));
  if (! t)
    RET (octave_value (Matrix (0, 0)));
  octave_scalar_map m;
  m.assign ("id", octave_value (static_cast<double> (id)));
  m.assign ("name", strv (btf__name_by_offset (btf, t->name_off)));
  m.assign ("kind", octave_value (static_cast<double> (BTF_INFO_KIND (t->info))));
  m.assign ("vlen", octave_value (static_cast<double> (BTF_INFO_VLEN (t->info))));
  m.assign ("kind_flag", octave_value (static_cast<double> (BTF_INFO_KFLAG (t->info))));
  bool has_size = BTF_INFO_KIND (t->info) != BTF_KIND_INT
                  && BTF_INFO_KIND (t->info) != BTF_KIND_PTR
                  && BTF_INFO_KIND (t->info) != BTF_KIND_FWD
                  && BTF_INFO_KIND (t->info) != BTF_KIND_TYPEDEF
                  && BTF_INFO_KIND (t->info) != BTF_KIND_VOLATILE
                  && BTF_INFO_KIND (t->info) != BTF_KIND_CONST
                  && BTF_INFO_KIND (t->info) != BTF_KIND_RESTRICT
                  && BTF_INFO_KIND (t->info) != BTF_KIND_FUNC
                  && BTF_INFO_KIND (t->info) != BTF_KIND_VAR
                  && BTF_INFO_KIND (t->info) != BTF_KIND_DECL_TAG
                  && BTF_INFO_KIND (t->info) != BTF_KIND_TYPE_TAG;
  m.assign ("size", octave_value (has_size ? static_cast<double> (t->size) : 0.0));
  m.assign ("type", octave_value (static_cast<double> (t->type)));
  RET (octave_value (m));
}

HANDLER (h_btf_members)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  long id = arg_long (a, 1, "id");
  const struct btf_type *t = btf__type_by_id (btf, static_cast<__u32> (id));
  __u32 kind = t ? BTF_INFO_KIND (t->info) : 0;
  if (! t || (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION))
    RET (octave_value (Matrix (0, 0)));

  __u32 vlen = BTF_INFO_VLEN (t->info);
  bool kflag = BTF_INFO_KFLAG (t->info) != 0;
  struct btf_member *mem = btf_members (t);

  // Every field is a 1xN cell so that octave_map::assign() produces a proper
  // 1xN struct array (one element per member) rather than a scalar struct
  // holding cells.
  octave_idx_type n = static_cast<octave_idx_type> (vlen);
  Cell names (dim_vector (1, n));
  Cell types (dim_vector (1, n));
  Cell offsets (dim_vector (1, n));
  Cell bitfields (dim_vector (1, n));
  Cell bytes (dim_vector (1, n));

  for (octave_idx_type k = 0; k < n; k++)
    {
      __u32 raw = mem[k].offset;
      double off = kflag ? static_cast<double> (raw & 0xffffff)
                         : static_cast<double> (raw);
      double bsz = kflag ? static_cast<double> (raw >> 24) : 0.0;
      names(k) = octave_value (string (btf__name_by_offset (btf, mem[k].name_off)));
      types(k) = octave_value (static_cast<double> (mem[k].type));
      offsets(k) = octave_value (off);
      bitfields(k) = octave_value (bsz);
      bytes(k) = octave_value (off / 8.0);
    }

  octave_map mp;
  mp.assign ("name", names);
  mp.assign ("type", types);
  mp.assign ("offset", offsets);
  mp.assign ("bitfield", bitfields);
  mp.assign ("bytes", bytes);
  RET (octave_value (mp));
}

HANDLER (h_btf_raw_data)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  __u32 sz = 0;
  const void *p = btf__raw_data (btf, &sz);
  RET (bytes_value (p, sz));
}

namespace {

struct DumpCtx
{
  string *out;
};

void
btf_dump_cb (void *ctx, const char *fmt, va_list args)
{
  DumpCtx *d = static_cast<DumpCtx *> (ctx);
  char tmp[4096];
  int n = std::vsnprintf (tmp, sizeof (tmp), fmt, args);
  if (n > 0)
    d->out->append (tmp, static_cast<size_t> (n));
}

}  // anonymous namespace

HANDLER (h_btf_dump)
{
  struct btf *btf = checked<struct btf> (arg_u64 (a, 0, "btf"), "btf");
  string out;
  DumpCtx ctx;
  ctx.out = &out;
  struct btf_dump_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  struct btf_dump *d = btf_dump__new (btf, btf_dump_cb, &ctx, &o);
  long err = libbpf_get_error (d);
  if (err)
    fail_errno ("btf_dump", err);
  if (has (a, 1) && ! a(1).isempty ())
    {
      long id = arg_long (a, 1, "type_id");
      INT_CHECK (btf_dump__dump_type (d, static_cast<__u32> (id)), "btf_dump__dump_type");
    }
  else
    {
      __u32 cnt = btf__type_cnt (btf);
      for (__u32 i = 1; i < cnt; i++)
        btf_dump__dump_type (d, i);
    }
  btf_dump__free (d);
  RET (octave_value (out));
}

// ===========================================================================
// Low level bpf_*() wrappers
// ===========================================================================

HANDLER (h_prog_load_raw)
{
  ensure_init ();
  long type = arg_long (a, 0, "prog_type");
  string name = opt_str (a, 1, "");
  string license = opt_str (a, 2, "GPL");
  string insns = arg_bytes (a, 3, "insns");
  Opts opts (a, 4);
  if (insns.size () % sizeof (struct bpf_insn) != 0)
    fail ("prog_load_raw: instruction buffer size must be a multiple of 8");

  struct bpf_prog_load_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.expected_attach_type = static_cast<enum bpf_attach_type> (
    static_cast<long> (opts.num ("expected_attach_type", 0)));
  o.prog_flags = static_cast<__u32> (opts.num ("prog_flags", 0));
  o.prog_ifindex = static_cast<__u32> (opts.num ("prog_ifindex", 0));
  o.kern_version = static_cast<__u32> (opts.num ("kern_version", 0));
  o.attach_btf_id = static_cast<__u32> (opts.num ("attach_btf_id", 0));
  o.attach_prog_fd = static_cast<__u32> (opts.num ("attach_prog_fd", 0));
  o.attach_btf_obj_fd = static_cast<__u32> (opts.num ("attach_btf_obj_fd", 0));
  o.log_level = static_cast<__u32> (opts.num ("log_level", 1));
  size_t logsz = static_cast<size_t> (opts.num ("log_size", 1 << 20));
  if (logsz < 64)
    logsz = 64;
  string log (logsz, '\0');
  o.log_buf = &log[0];
  o.log_size = static_cast<__u32> (logsz);

  int fd = bpf_prog_load (static_cast<enum bpf_prog_type> (type),
                          name.empty () ? nullptr : name.c_str (),
                          license.c_str (),
                          reinterpret_cast<const struct bpf_insn *> (insns.data ()),
                          insns.size () / sizeof (struct bpf_insn), &o);
  if (fd < 0 && nargout > 1)
    {
      octave_value_list rv (2);
      rv(0) = intv (fd);
      rv(1) = octave_value (log);
      return rv;
    }
  INT_CHECK (fd, "prog_load");
  if (nargout > 1)
    {
      octave_value_list rv (2);
      rv(0) = intv (fd);
      rv(1) = octave_value (log);
      return rv;
    }
  RET (intv (fd));
}

HANDLER (h_prog_get_info)
{
  int fd = static_cast<int> (arg_long (a, 0, "fd"));
  struct bpf_prog_info info;
  std::memset (&info, 0, sizeof (info));
  __u32 len = sizeof (info);
  INT_CHECK (bpf_prog_get_info_by_fd (fd, &info, &len), "prog_get_info");
  octave_scalar_map m;
  m.assign ("type", octave_value (static_cast<double> (info.type)));
  m.assign ("id", octave_value (static_cast<double> (info.id)));
  m.assign ("tag", bytes_value (info.tag, sizeof (info.tag)));
  m.assign ("jit_jited_ksyms", octave_value (static_cast<double> (info.jited_ksyms)));
  m.assign ("xlated_prog_len", octave_value (static_cast<double> (info.xlated_prog_len)));
  m.assign ("n_runs", octave_value (static_cast<double> (info.run_cnt)));
  m.assign ("run_time_ns", octave_value (static_cast<double> (info.run_time_ns)));
  m.assign ("name", octave_value (string (reinterpret_cast<const char *> (info.name))));
  m.assign ("ifindex", octave_value (static_cast<double> (info.ifindex)));
  m.assign ("btf_id", octave_value (static_cast<double> (info.btf_id)));
  m.assign ("load_time", octave_value (static_cast<double> (info.load_time)));
  m.assign ("created_by_uid", octave_value (static_cast<double> (info.created_by_uid)));
  RET (octave_value (m));
}

HANDLER (h_prog_get_fd_by_id)
{
  long id = arg_long (a, 0, "id");
  int fd = bpf_prog_get_fd_by_id (static_cast<__u32> (id));
  INT_CHECK (fd, "prog_get_fd_by_id");
  RET (intv (fd));
}

HANDLER (h_prog_get_next_id)
{
  long id = opt_long (a, 0, 0);
  __u32 nid = 0;
  INT_CHECK (bpf_prog_get_next_id (static_cast<__u32> (id), &nid), "prog_get_next_id");
  RET (intv (nid));
}

HANDLER (h_prog_attach)
{
  int pfd = static_cast<int> (arg_long (a, 0, "prog_fd"));
  int tfd = static_cast<int> (arg_long (a, 1, "target_fd"));
  long at = arg_long (a, 2, "attach_type");
  long flags = opt_long (a, 3, 0);
  INT_CHECK (bpf_prog_attach (pfd, tfd, static_cast<enum bpf_attach_type> (at),
                              static_cast<unsigned int> (flags)),
             "prog_attach");
  RET0 ();
}

HANDLER (h_prog_detach)
{
  int tfd = static_cast<int> (arg_long (a, 0, "target_fd"));
  long at = arg_long (a, 1, "attach_type");
  int pfd = static_cast<int> (opt_long (a, 2, 0));
  INT_CHECK (bpf_prog_detach2 (pfd, tfd, static_cast<enum bpf_attach_type> (at)),
             "prog_detach");
  RET0 ();
}

HANDLER (h_prog_bind_map)
{
  int pfd = static_cast<int> (arg_long (a, 0, "prog_fd"));
  int mfd = static_cast<int> (arg_long (a, 1, "map_fd"));
  INT_CHECK (bpf_prog_bind_map (pfd, mfd, nullptr), "prog_bind_map");
  RET0 ();
}

HANDLER (h_raw_tracepoint_open)
{
  string name = opt_str (a, 0, "");
  int pfd = static_cast<int> (opt_long (a, 1, 0));
  int fd = bpf_raw_tracepoint_open (name.empty () ? nullptr : name.c_str (), pfd);
  INT_CHECK (fd, "raw_tracepoint_open");
  RET (intv (fd));
}

HANDLER (h_link_create)
{
  int pfd = static_cast<int> (arg_long (a, 0, "prog_fd"));
  long at = arg_long (a, 1, "attach_type");
  int tfd = static_cast<int> (opt_long (a, 2, 0));
  long flags = opt_long (a, 3, 0);
  struct bpf_link_create_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.flags = static_cast<__u32> (flags);
  int fd = bpf_link_create (pfd, tfd, static_cast<enum bpf_attach_type> (at), &o);
  INT_CHECK (fd, "link_create");
  RET (intv (fd));
}

HANDLER (h_btf_load)
{
  string data = arg_bytes (a, 0, "btf_data");
  long log_level = opt_long (a, 1, 0);
  size_t log_size = static_cast<size_t> (opt_long (a, 2, 1 << 20));
  if (log_size < 64)
    log_size = 64;
  string log (log_size, '\0');
  struct bpf_btf_load_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.btf_flags = static_cast<__u32> (opt_long (a, 3, 0));
  if (log_level > 0)
    {
      o.log_level = static_cast<__u32> (log_level);
      o.log_buf = &log[0];
      o.log_size = static_cast<__u32> (log_size);
    }
  int fd = bpf_btf_load (data.data (), data.size (), &o);
  if (nargout > 1)
    {
      octave_value_list rv (2);
      rv(0) = intv (fd);
      rv(1) = octave_value (log);
      return rv;
    }
  INT_CHECK (fd, "btf_load");
  RET (intv (fd));
}

HANDLER (h_prog_get_next_id_or_zero)
{
  __u32 id = 0;
  int r = bpf_prog_get_next_id (0, &id);
  if (r)
    RET (intv (0));
  RET (intv (id));
}

HANDLER (h_enable_stats)
{
  long type = arg_long (a, 0, "type");
  INT_CHECK (bpf_enable_stats (static_cast<enum bpf_stats_type> (type)), "enable_stats");
  RET0 ();
}

HANDLER (h_xdp_attach)
{
  int ifindex = static_cast<int> (arg_long (a, 0, "ifindex"));
  int pfd = static_cast<int> (arg_long (a, 1, "prog_fd"));
  long flags = opt_long (a, 2, 0);
  struct bpf_xdp_attach_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.old_prog_fd = static_cast<int> (opt_long (a, 3, 0));
  INT_CHECK (bpf_xdp_attach (ifindex, pfd, static_cast<__u32> (flags), &o), "xdp_attach");
  RET0 ();
}

HANDLER (h_xdp_detach)
{
  int ifindex = static_cast<int> (arg_long (a, 0, "ifindex"));
  long flags = opt_long (a, 1, 0);
  struct bpf_xdp_attach_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  o.old_prog_fd = static_cast<int> (opt_long (a, 2, 0));
  INT_CHECK (bpf_xdp_detach (ifindex, static_cast<__u32> (flags), &o), "xdp_detach");
  RET0 ();
}

HANDLER (h_xdp_query)
{
  int ifindex = static_cast<int> (arg_long (a, 0, "ifindex"));
  long flags = opt_long (a, 1, 0);
  struct bpf_xdp_query_opts o;
  std::memset (&o, 0, sizeof (o));
  o.sz = sizeof (o);
  INT_CHECK (bpf_xdp_query (ifindex, static_cast<int> (flags), &o), "xdp_query");
  octave_scalar_map m;
  m.assign ("prog_id", octave_value (static_cast<double> (o.prog_id)));
  m.assign ("drv_prog_id", octave_value (static_cast<double> (o.drv_prog_id)));
  m.assign ("hw_prog_id", octave_value (static_cast<double> (o.hw_prog_id)));
  m.assign ("skb_prog_id", octave_value (static_cast<double> (o.skb_prog_id)));
  m.assign ("attach_mode", octave_value (static_cast<double> (o.attach_mode)));
  m.assign ("feature_flags", octave_value (static_cast<double> (o.feature_flags)));
  RET (octave_value (m));
}

// ===========================================================================
// Object support: resolving an attach specification (used by bpf.Object)
// ===========================================================================

HANDLER (h_attach_auto)
{
  struct bpf_program *p =
    checked<struct bpf_program> (arg_u64 (a, 0, "prog"), "program");
  string sec = bpf_program__section_name (p);
  string name = bpf_program__name (p);
  struct bpf_link *l = nullptr;

  auto starts_with = [] (const string &s, const char *pfx) {
    size_t n = std::strlen (pfx);
    return s.size () >= n && s.compare (0, n, pfx) == 0;
  };
  auto after = [] (const string &s, size_t n) { return s.substr (n); };

  if (starts_with (sec, "kprobe/"))
    l = bpf_program__attach_kprobe (p, false, after (sec, 7).c_str ());
  else if (starts_with (sec, "kretprobe/"))
    l = bpf_program__attach_kprobe (p, true, after (sec, 10).c_str ());
  else if (starts_with (sec, "ksyscall/"))
    {
      struct bpf_ksyscall_opts o;
      std::memset (&o, 0, sizeof (o));
      o.sz = sizeof (o);
      l = bpf_program__attach_ksyscall (p, after (sec, 9).c_str (), &o);
    }
  else if (starts_with (sec, "krsyscall/"))
    {
      struct bpf_ksyscall_opts o;
      std::memset (&o, 0, sizeof (o));
      o.sz = sizeof (o);
      o.retprobe = true;
      l = bpf_program__attach_ksyscall (p, after (sec, 10).c_str (), &o);
    }
  else if (starts_with (sec, "raw_tp/") || starts_with (sec, "raw_tracepoint/"))
    {
      size_t n = starts_with (sec, "raw_tp/") ? 7 : 15;
      l = bpf_program__attach_raw_tracepoint (p, after (sec, n).c_str ());
    }
  else if (starts_with (sec, "tracepoint/") || starts_with (sec, "tp/"))
    {
      size_t n = starts_with (sec, "tracepoint/") ? 11 : 3;
      string rest = after (sec, n);
      size_t slash = rest.find ('/');
      if (slash == string::npos)
        fail ("cannot parse tracepoint section '" + sec + "'");
      string cat = rest.substr (0, slash);
      string nm = rest.substr (slash + 1);
      l = bpf_program__attach_tracepoint (p, cat.c_str (), nm.c_str ());
    }
  else if (starts_with (sec, "fentry/") || starts_with (sec, "fexit/")
           || starts_with (sec, "fmod_ret/") || starts_with (sec, "lsm/")
           || starts_with (sec, "struct_ops"))
    {
      if (starts_with (sec, "lsm/"))
        l = bpf_program__attach_lsm (p);
      else
        l = bpf_program__attach_trace (p);
    }
  else if (starts_with (sec, "iter/") || starts_with (sec, "iter"))
    {
      struct bpf_iter_attach_opts o;
      std::memset (&o, 0, sizeof (o));
      o.sz = sizeof (o);
      l = bpf_program__attach_iter (p, &o);
    }
  else if (starts_with (sec, "xdp"))
    fail ("cannot auto attach XDP program '" + name + "': use attach_xdp(ifindex)");
  else
    fail ("cannot auto attach program '" + name + "' from section '" + sec + "'");

  long err = libbpf_get_error (l);
  if (err)
    fail_errno ("attach '" + name + "' (" + sec + ")", err);
  reg_add (l, "link");
  RET (u64v (reinterpret_cast<uint64_t> (l)));
}

// ===========================================================================
// Dispatch table
// ===========================================================================

struct Entry
{
  const char *name;
  octave_value_list (*fn) (const octave_value_list &, int);
};

const Entry g_table[] = {
  { "version", h_version },
  { "strerror", h_strerror },
  { "type_str", h_type_str },
  { "set_print_level", h_set_print_level },
  { "get_print_level", h_get_print_level },
  { "commands", h_commands },
  { "set_capture", h_set_capture },
  { "get_log", h_get_log },
  { "clear_log", h_clear_log },
  { "probe_prog_type", h_probe_prog_type },
  { "probe_map_type", h_probe_map_type },
  { "probe_helper", h_probe_helper },
  { "num_possible_cpus", h_num_possible_cpus },
  { "prog_type_by_name", h_prog_type_by_name },
  { "attach_type_by_name", h_attach_type_by_name },
  { "find_vmlinux_btf_id", h_find_vmlinux_btf_id },
  { "handle_kind", h_handle_kind },
  { "set_memlock_rlim", h_set_memlock_rlim },

  { "object_open_file", h_object_open_file },
  { "object_open_mem", h_object_open_mem },
  { "object_load", h_object_load },
  { "object_prepare", h_object_prepare },
  { "object_close", h_object_close },
  { "object_name", h_object_name },
  { "object_kversion", h_object_kversion },
  { "object_set_kversion", h_object_set_kversion },
  { "object_btf_fd", h_object_btf_fd },
  { "object_btf", h_object_btf },
  { "object_token_fd", h_object_token_fd },
  { "object_find_program", h_object_find_program },
  { "object_find_map", h_object_find_map },
  { "object_find_map_fd", h_object_find_map_fd },
  { "object_programs", h_object_programs },
  { "object_maps", h_object_maps },
  { "object_pin", h_object_pin },
  { "object_unpin", h_object_unpin },
  { "object_pin_maps", h_object_pin_maps },
  { "object_unpin_maps", h_object_unpin_maps },
  { "object_pin_programs", h_object_pin_programs },
  { "object_unpin_programs", h_object_unpin_programs },
  { "object_set_log", h_object_set_log },

  { "program_fd", h_program_fd },
  { "program_name", h_program_name },
  { "program_section_name", h_program_section_name },
  { "program_type", h_program_type },
  { "program_set_type", h_program_set_type },
  { "program_expected_attach_type", h_program_expected_attach_type },
  { "program_set_expected_attach_type", h_program_set_expected_attach_type },
  { "program_autoload", h_program_autoload },
  { "program_set_autoload", h_program_set_autoload },
  { "program_autoattach", h_program_autoattach },
  { "program_set_autoattach", h_program_set_autoattach },
  { "program_insns", h_program_insns },
  { "program_insn_cnt", h_program_insn_cnt },
  { "program_set_insns", h_program_set_insns },
  { "program_log_level", h_program_log_level },
  { "program_set_log_level", h_program_set_log_level },
  { "program_set_log_buf", h_program_set_log_buf },
  { "program_get_log", h_program_get_log },
  { "program_set_attach_target", h_program_set_attach_target },
  { "program_set_flags", h_program_set_flags },
  { "program_flags", h_program_flags },
  { "program_pin", h_program_pin },
  { "program_unpin", h_program_unpin },
  { "program_unload", h_program_unload },
  { "program_set_ifindex", h_program_set_ifindex },
  { "program_attach", h_program_attach },
  { "program_attach_kprobe", h_program_attach_kprobe },
  { "program_attach_kprobe_multi", h_program_attach_kprobe_multi },
  { "program_attach_uprobe", h_program_attach_uprobe },
  { "program_attach_uprobe_multi", h_program_attach_uprobe_multi },
  { "program_attach_tracepoint", h_program_attach_tracepoint },
  { "program_attach_raw_tracepoint", h_program_attach_raw_tracepoint },
  { "program_attach_trace", h_program_attach_trace },
  { "program_attach_lsm", h_program_attach_lsm },
  { "program_attach_cgroup", h_program_attach_cgroup },
  { "program_attach_netns", h_program_attach_netns },
  { "program_attach_xdp", h_program_attach_xdp },
  { "program_attach_sockmap", h_program_attach_sockmap },
  { "program_attach_freplace", h_program_attach_freplace },
  { "program_attach_netfilter", h_program_attach_netfilter },
  { "program_attach_tcx", h_program_attach_tcx },
  { "program_attach_netkit", h_program_attach_netkit },
  { "program_attach_iter", h_program_attach_iter },
  { "program_attach_usdt", h_program_attach_usdt },
  { "program_attach_perf_event", h_program_attach_perf_event },
  { "program_attach_ksyscall", h_program_attach_ksyscall },
  { "program_attach_tracing_multi", h_program_attach_tracing_multi },
  { "program_test_run", h_program_test_run },

  { "link_fd", h_link_fd },
  { "link_destroy", h_link_destroy },
  { "link_detach", h_link_detach },
  { "link_disconnect", h_link_disconnect },
  { "link_pin", h_link_pin },
  { "link_unpin", h_link_unpin },
  { "link_pin_path", h_link_pin_path },
  { "link_update_program", h_link_update_program },
  { "link_update_map", h_link_update_map },
  { "link_open", h_link_open },

  { "map_fd", h_map_fd },
  { "map_name", h_map_name },
  { "map_type", h_map_type },
  { "map_set_type", h_map_set_type },
  { "map_key_size", h_map_key_size },
  { "map_value_size", h_map_value_size },
  { "map_max_entries", h_map_max_entries },
  { "map_map_flags", h_map_map_flags },
  { "map_set_max_entries", h_map_set_max_entries },
  { "map_set_map_flags", h_map_set_map_flags },
  { "map_set_key_size", h_map_set_key_size },
  { "map_set_value_size", h_map_set_value_size },
  { "map_btf_key_type_id", h_map_btf_key_type_id },
  { "map_btf_value_type_id", h_map_btf_value_type_id },
  { "map_is_internal", h_map_is_internal },
  { "map_reuse_fd", h_map_reuse_fd },
  { "map_set_inner_map_fd", h_map_set_inner_map_fd },
  { "map_inner_map", h_map_inner_map },
  { "map_pin", h_map_pin },
  { "map_unpin", h_map_unpin },
  { "map_set_pin_path", h_map_set_pin_path },
  { "map_pin_path", h_map_pin_path },
  { "map_is_pinned", h_map_is_pinned },
  { "map_lookup", h_map_lookup },
  { "map_update", h_map_update },
  { "map_delete", h_map_delete },
  { "map_lookup_and_delete", h_map_lookup_and_delete },
  { "map_get_next_key", h_map_get_next_key },
  { "map_lookup_fd", h_map_lookup_fd },
  { "map_update_fd", h_map_update_fd },
  { "map_delete_fd", h_map_delete_fd },
  { "map_next_key_fd", h_map_next_key_fd },
  { "map_create", h_map_create },
  { "map_freeze", h_map_freeze },
  { "close_fd", h_close_fd },
  { "map_get_fd_by_id", h_map_get_fd_by_id },
  { "map_get_next_id", h_map_get_next_id },
  { "map_get_info", h_map_get_info },
  { "obj_get", h_obj_get },
  { "obj_pin", h_obj_pin },

  { "ringbuf_new", h_ringbuf_new },
  { "ringbuf_add", h_ringbuf_add },
  { "ringbuf_free", h_ringbuf_free },
  { "ringbuf_poll", h_ringbuf_poll },
  { "ringbuf_consume", h_ringbuf_consume },
  { "ringbuf_epoll_fd", h_ringbuf_epoll_fd },

  { "perfbuf_new", h_perfbuf_new },
  { "perfbuf_free", h_perfbuf_free },
  { "perfbuf_poll", h_perfbuf_poll },
  { "perfbuf_consume", h_perfbuf_consume },
  { "perfbuf_buffer_cnt", h_perfbuf_buffer_cnt },
  { "perfbuf_epoll_fd", h_perfbuf_epoll_fd },

  { "btf_parse_elf", h_btf_parse_elf },
  { "btf_parse_raw", h_btf_parse_raw },
  { "btf_new_empty", h_btf_new_empty },
  { "btf_load_vmlinux", h_btf_load_vmlinux },
  { "btf_load_from_kernel_by_id", h_btf_load_from_kernel_by_id },
  { "btf_load_into_kernel", h_btf_load_into_kernel },
  { "btf_free", h_btf_free },
  { "btf_fd", h_btf_fd },
  { "btf_type_cnt", h_btf_type_cnt },
  { "btf_find_by_name", h_btf_find_by_name },
  { "btf_find_by_name_kind", h_btf_find_by_name_kind },
  { "btf_name_by_offset", h_btf_name_by_offset },
  { "btf_type_info", h_btf_type_info },
  { "btf_members", h_btf_members },
  { "btf_raw_data", h_btf_raw_data },
  { "btf_dump", h_btf_dump },

  { "prog_load", h_prog_load_raw },
  { "prog_get_info", h_prog_get_info },
  { "prog_get_fd_by_id", h_prog_get_fd_by_id },
  { "prog_get_next_id", h_prog_get_next_id },
  { "prog_attach", h_prog_attach },
  { "prog_detach", h_prog_detach },
  { "prog_bind_map", h_prog_bind_map },
  { "raw_tracepoint_open", h_raw_tracepoint_open },
  { "link_create", h_link_create },
  { "btf_load", h_btf_load },
  { "first_prog_id", h_prog_get_next_id_or_zero },
  { "enable_stats", h_enable_stats },
  { "xdp_attach", h_xdp_attach },
  { "xdp_detach", h_xdp_detach },
  { "xdp_query", h_xdp_query },

  { "attach_auto", h_attach_auto },

  { nullptr, nullptr }
};

HANDLER (h_commands)
{
  std::vector<string> names;
  for (const Entry *e = g_table; e->name; ++e)
    names.push_back (e->name);
  std::sort (names.begin (), names.end ());
  Cell c (dim_vector (1, static_cast<octave_idx_type> (names.size ())));
  for (size_t i = 0; i < names.size (); i++)
    c(static_cast<octave_idx_type> (i)) = octave_value (names[i]);
  RET (octave_value (c));
}

}  // anonymous namespace

// ---------------------------------------------------------------------------
// DEFUN
// ---------------------------------------------------------------------------

using std::string;

DEFUN_DLD (libbpf_wrap, args, nargout,
  "-*- texinfo -*-\n\
@deftypefn {} {@var{ret} =} libbpf_wrap (@var{command}, @dots{})\n\
\n\
Low level interface to libbpf.  This function is not meant to be called\n\
directly; use the @code{bpf_*} functions and the @code{+bpf} class\n\
hierarchy of the @code{octave_libbpf} package instead.\n\
@end deftypefn")
{
  if (args.length () < 1)
    error ("libbpf_wrap: missing command argument");

  if (! args(0).is_string ())
    error ("libbpf_wrap: command must be a string");

  ensure_init ();

  string cmd = args(0).string_value ();

  // The command is stripped from the argument list handed to the handler.
  octave_value_list rest (args.length () - 1);
  for (octave_idx_type i = 1; i < args.length (); i++)
    rest(i - 1) = args(i);

  for (const Entry *e = g_table; e->name; e++)
    {
      if (cmd == e->name)
        return e->fn (rest, nargout);
    }

  error ("libbpf_wrap: unknown command '%s'", cmd.c_str ());
}
