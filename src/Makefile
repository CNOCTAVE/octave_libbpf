## Makefile for the octave_libbpf oct-file.
##
## This file is intentionally forgiving: libbpf can be picked up from
##   1. $(LIBBPF_ROOT)            (explicit override, must contain libbpf.h)
##   2. ../libbpf, ../../libbpf   (a libbpf source tree, as shipped here)
##   3. /usr/include/bpf          (libbpf-devel)
##   4. src/vendor/bpf            (headers bundled with this package)
## and the shared library is located with pkg-config if available, otherwise by
## scanning the usual library directories (including versioned libbpf.so.1,
## which is all that a plain "dnf install libbpf" provides).

MKOCTFILE ?= mkoctfile
OCTAVE    ?= octave
CC        ?= cc

SRCDIR  := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
PKGDIR  := $(patsubst %/,%,$(dir $(SRCDIR)))
BUILD   := $(SRCDIR)/.build
SHIM    := $(BUILD)/include
TARGET  := libbpf_wrap.oct
SOURCES := libbpf_wrap.cc

QUIET   ?= @
override V := $(if $(filter 1 yes true,$(V)),1,)

## ---------------------------------------------------------------------------
## Locate headers
## ---------------------------------------------------------------------------

ifneq ($(strip $(LIBBPF_ROOT)),)
  ifeq ($(wildcard $(LIBBPF_ROOT)/libbpf.h),)
    $(error LIBBPF_ROOT="$(LIBBPF_ROOT)" does not contain libbpf.h)
  endif
  BPF_INC_ROOT := $(LIBBPF_ROOT)
  BPF_UAPI_DIRS := $(wildcard $(LIBBPF_ROOT)/../include/uapi $(LIBBPF_ROOT)/../../include/uapi)
  USE_SHIM := 1
else ifneq ($(wildcard $(PKGDIR)/libbpf/src/libbpf.h),)
  BPF_INC_ROOT := $(PKGDIR)/libbpf/src
  BPF_UAPI_DIRS := $(PKGDIR)/libbpf/include/uapi $(PKGDIR)/libbpf/include
  USE_SHIM := 1
else ifneq ($(wildcard $(PKGDIR)/../libbpf/src/libbpf.h),)
  BPF_INC_ROOT := $(PKGDIR)/../libbpf/src
  BPF_UAPI_DIRS := $(PKGDIR)/../libbpf/include/uapi $(PKGDIR)/../libbpf/include
  USE_SHIM := 1
else ifneq ($(wildcard /usr/include/bpf/libbpf.h),)
  BPF_INC_ROOT := /usr/include/bpf
  BPF_UAPI_DIRS :=
  USE_SHIM := 1
else ifneq ($(wildcard $(SRCDIR)/vendor/bpf/libbpf.h),)
  BPF_INC_ROOT := $(SRCDIR)/vendor/bpf
  BPF_UAPI_DIRS := $(SRCDIR)/vendor
  USE_SHIM := 1
else
  $(error Cannot find libbpf headers.  Install libbpf-devel, keep a libbpf \
          source tree next to this package, or set LIBBPF_ROOT=/path/to/libbpf/src)
endif

BPF_HEADER_FLAGS := -I$(SHIM) $(addprefix -I,$(BPF_UAPI_DIRS))

## ---------------------------------------------------------------------------
## Locate the shared library
## ---------------------------------------------------------------------------

LIB_SEARCH_DIRS := /usr/lib64 /usr/lib /lib64 /lib /usr/local/lib64 \
                   /usr/local/lib /usr/lib/x86_64-linux-gnu \
                   /usr/lib/aarch64-linux-gnu

ifneq ($(shell command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf 2>/dev/null && echo yes),)
  LIBBPF_LIBS := $(shell pkg-config --libs libbpf)
  LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
  LIBBPF_FOUND := "pkg-config"
else
  FOUND_SO := $(firstword $(foreach d,$(LIB_SEARCH_DIRS),$(wildcard $(d)/libbpf.so)))
  FOUND_SO1 := $(firstword $(foreach d,$(LIB_SEARCH_DIRS),$(wildcard $(d)/libbpf.so.1) $(wildcard $(d)/libbpf.so.*)))
  ifneq ($(strip $(FOUND_SO)),)
    LIBBPF_LIBS := -L$(dir $(FOUND_SO)) -lbpf
    LIBBPF_FOUND := $(FOUND_SO)
  else ifneq ($(strip $(FOUND_SO1)),)
    LIBBPF_LIBS := -L$(dir $(FOUND_SO1)) -l:$(notdir $(FOUND_SO1))
    LIBBPF_FOUND := $(FOUND_SO1)
  else
    $(error Cannot find libbpf.so or libbpf.so.1.  Install the libbpf runtime \
            (dnf install libbpf) or set LIBBPF_LIBS=-L... -l...)
  endif
endif

## Allow the user to override everything.
LIBBPF_LIBS   ?=
LIBBPF_CFLAGS ?=

MKOCTFILE_FLAGS := $(BPF_HEADER_FLAGS) $(LIBBPF_CFLAGS) \
                   -Wno-deprecated-declarations

## ---------------------------------------------------------------------------
## Targets
## ---------------------------------------------------------------------------

.PHONY: all clean distclean check info

all: $(TARGET)

$(SHIM)/bpf:
	$(QUIET)mkdir -p $(SHIM)
	$(QUIET)ln -sfn $(BPF_INC_ROOT) $(SHIM)/bpf

$(TARGET): $(SOURCES) Makefile | $(SHIM)/bpf
	@echo "  MKOCTFILE  $@  (libbpf: $(LIBBPF_FOUND))"
	$(QUIET)$(MKOCTFILE) -o $@ $(SOURCES) $(MKOCTFILE_FLAGS) $(LIBBPF_LIBS)

info:
	@echo "libbpf headers : $(BPF_INC_ROOT)"
	@echo "libbpf library : $(LIBBPF_FOUND)"
	@echo "libbpf libs    : $(LIBBPF_LIBS)"
	@echo "include flags  : $(BPF_HEADER_FLAGS) $(LIBBPF_CFLAGS)"

clean:
	$(QUIET)rm -f $(TARGET) $(SOURCES:.cc=.o) $(SOURCES:.cc=.d)
	$(QUIET)rm -rf $(BUILD)

distclean: clean

check: all
	$(QUIET)cd $(PKGDIR) && $(OCTAVE) --no-gui --quiet --eval \
	  "addpath('$(SRCDIR)','$(PKGDIR)/inst'); disp(libbpf_wrap('version'));"
