SYSTEMD_DIR ?= $(wildcard /etc/systemd/system)
PREFIX ?= /usr/local

.PHONY: all install

all:
	: nothing to do, run make [PREFIX=..] [SYSTEMD_DIR=..] install to install

$(PREFIX)/sbin/ocsp-proxy:
	install -Dp -m0755 ocsp-proxy.pl $@

$(SYSTEMD_DIR)/ocsp-proxy.service: systemd/ocsp-proxy.service
	sed -r -e 's|^(ExecStart=).*(/ocsp-proxy )|\1$(PREFIX)/sbin\2|g' $< > $@
	systemctl enable ocsp-proxy.service --now

ifneq ("$(SYSTEMD_DIR)","")
install: $(PREFIX)/sbin/ocsp-proxy $(SYSTEMD_DIR)/ocsp-proxy.service
else
install: $(PREFIX)/sbin/ocsp-proxy
endif
