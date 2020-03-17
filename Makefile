SYSTEMD_DIR ?= $(wildcard /lib/systemd/system)
PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
TEST_BIN := $(wildcard /bin/test)
TEST_BIN := $(if $(TEST_BIN),$(TEST_BIN),$(wildcard /usr/bin/test))

.PHONY: all install

all:
	: nothing to do, run make [PREFIX=..|SBINDIR=..] [SYSTEMD_DIR=..] install to install

$(SBINDIR)/ocsp_proxy:
	install -Dp -m0755 ocsp_proxy.pl $(DESTDIR)$@

$(SYSTEMD_DIR)/ocsp_proxy.service: systemd/ocsp_proxy.service
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	sed -r -e 's|@@TEST_BIN@@|$(TEST_BIN)|;s|@@SBINDIR@@|$(SBINDIR)|g' $< > $(DESTDIR)$@

install: $(SBINDIR)/ocsp_proxy $(if $(SYSTEMD_DIR),$(SYSTEMD_DIR)/ocsp_proxy.service,)
