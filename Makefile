SYSTEMD_DIR ?= $(wildcard /etc/systemd/system)
PREFIX ?= /usr/local

.PHONY: all install

all:
	: nothing to do, run make [PREFIX=..] [SYSTEMD_DIR=..] install to install

$(PREFIX)/sbin/ocsp_proxy:
	install -Dp -m0755 ocsp_proxy.pl $(DESTDIR)$@

$(SYSTEMD_DIR)/ocsp_proxy.service: systemd/ocsp_proxy.service
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	sed -r -e 's|^(ExecStart=).*(/ocsp_proxy )|\1$(PREFIX)/sbin\2|g' $< > $(DESTDIR)$@
	systemctl enable ocsp_proxy.service --now

ifneq ("$(SYSTEMD_DIR)","")
install: $(PREFIX)/sbin/ocsp_proxy $(SYSTEMD_DIR)/ocsp_proxy.service
else
install: $(PREFIX)/sbin/ocsp_proxy
endif
