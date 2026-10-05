## Convenience driver for the octave_libbpf package.
##
##   make            build the oct-file
##   make dist       create ../octave_libbpf-<version>.tar.gz
##   make install    install the tarball with pkg install
##   make test       install the tarball and run the test suite
##   make examples   run every example against the installed package
##   make clean      remove build products

PKGDIR   := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
PKGNAME  := $(notdir $(PKGDIR))
PARENT   := $(patsubst %/,%,$(dir $(PKGDIR)))
VERSION  := $(shell sed -n 's/^Version:[[:space:]]*//p' $(PKGDIR)/DESCRIPTION | tr -d '[:space:]')
BASENAME := $(PKGNAME)-$(VERSION)
DIST     := $(PARENT)/$(BASENAME).tar.gz
OCTAVE   ?= octave
EXAMPLES := map_from_octave test_run hello_kprobe ringbuf_tracepoint

.PHONY: all dist install test examples clean

all:
	$(MAKE) -C $(PKGDIR)/src

## Always rebuild the tarball from a clean source tree.
dist:
	@echo "  DIST    $(DIST)"
	@rm -rf $(PKGDIR)/src/.build $(PKGDIR)/src/*.oct $(PKGDIR)/src/*.o
	@rm -f $(DIST)
	@cd $(PARENT) && tar --exclude='.git' --exclude='.build' \
	     --exclude='*.oct' --exclude='*.o' --exclude='*.mex' \
	     -czf $(BASENAME).tar.gz $(PKGNAME)
	@echo "  wrote   $(DIST) ($$(stat -c %s $(DIST)) bytes)"

install: dist
	$(OCTAVE) --no-gui --quiet --eval "pkg install $(DIST)"

test: dist
	$(OCTAVE) --no-gui --quiet --eval \
	  "pkg install $(DIST); pkg load $(PKGNAME); pkg test $(PKGNAME)"

examples:
	@for e in $(EXAMPLES); do \
	  echo "=== $$e ==="; \
	  $(OCTAVE) --no-gui --quiet --eval \
	    "pkg load $(PKGNAME); run('$(PKGDIR)/examples/$$e.m')" || exit 1; \
	done

clean:
	-$(MAKE) -C $(PKGDIR)/src clean
	rm -f $(DIST)
