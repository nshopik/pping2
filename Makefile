# should only need to change LIBTINS to the libtins install prefix
# (typically /usr/local unless overridden when tins built)
LIBTINS = $(HOME)/src/libtins
CPPFLAGS += -I$(LIBTINS)/include
LDFLAGS += -L$(LIBTINS)/lib -ltins -lpcap
CXXFLAGS += -std=c++17 -g -O3 -Wall

# Hardening: pping runs as root briefly to open the packet socket and
# then parses untrusted packets via libtins. Make a parse-time memory bug
# harder to exploit. _FORTIFY_SOURCE requires -O1 or higher.
CXXFLAGS += -fstack-protector-strong -fPIE \
            -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
            -Wformat -Wformat-security -Werror=format-security
# Linux-only link hardening; macOS/BSD ld either default to PIE or reject -z flags.
ifeq ($(shell uname -s),Linux)
LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
endif

# --- Install paths and packaging variables ---
PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc
SHAREDIR    ?= $(PREFIX)/share/pping
DESTDIR     ?=

pping:  pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o pping pping.cpp $(LDFLAGS)

check: pping test/unit_tests
	@cd test && sh run_tests.sh

test/unit_tests: test/unit_tests.cpp pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o test/unit_tests test/unit_tests.cpp $(LDFLAGS)

clean:
	rm -f pping test/unit_tests

# Regenerate test fixtures from test/synth/. Requires scapy.
pcaps:
	cd test && python3 -m synth.build

# Path substitution applied at install time so the shipped contrib/ scripts
# work under arbitrary PREFIX/SYSCONFDIR. Source files keep /usr/local/bin
# and /etc/default literals so they remain runnable from a checkout.
SUBST = sed \
    -e "s|/usr/local/bin|$(PREFIX)/bin|g" \
    -e "s|/etc/default/pping|$(SYSCONFDIR)/default/pping|g"

# --- Install / uninstall ---

install: pping
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 pping $(DESTDIR)$(PREFIX)/bin/pping
ifeq ($(shell uname -s),Linux)
	if [ -z "$(DESTDIR)" ]; then \
	    setcap cap_net_raw+ep $(PREFIX)/bin/pping; \
	else \
	    echo ""; \
	    echo "WARNING: setcap skipped because DESTDIR is set."; \
	    echo "Apply in your packaging postinst (or run manually):"; \
	    echo "  setcap cap_net_raw+ep $(PREFIX)/bin/pping"; \
	fi
endif

install-systemd:
	install -d $(DESTDIR)$(SYSCONFDIR)/systemd/system
	$(SUBST) contrib/systemd/pping.service \
	    > $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping.service
	chmod 0644 $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping.service
	install -d $(DESTDIR)$(SYSCONFDIR)/default
	if [ ! -e $(DESTDIR)$(SYSCONFDIR)/default/pping ] \
	   && [ ! -L $(DESTDIR)$(SYSCONFDIR)/default/pping ]; then \
	    install -m 0644 contrib/systemd/pping.default \
	        $(DESTDIR)$(SYSCONFDIR)/default/pping; \
	fi
	if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi
	@echo
	@echo "Edit $(SYSCONFDIR)/default/pping (set PPING_IFACE), then:"
	@echo "  sudo systemctl enable --now pping"

install-clickhouse:
	install -d $(DESTDIR)$(PREFIX)/bin
	$(SUBST) contrib/clickhouse/pping-load.sh \
	    > $(DESTDIR)$(PREFIX)/bin/pping-load.sh
	chmod 0755 $(DESTDIR)$(PREFIX)/bin/pping-load.sh
	install -d $(DESTDIR)$(SYSCONFDIR)/cron.d
	$(SUBST) contrib/clickhouse/pping-load.cron \
	    > $(DESTDIR)$(SYSCONFDIR)/cron.d/pping-load
	chmod 0644 $(DESTDIR)$(SYSCONFDIR)/cron.d/pping-load
	install -d $(DESTDIR)$(SHAREDIR)
	install -m 0644 contrib/clickhouse/schema.sql \
	    $(DESTDIR)$(SHAREDIR)/schema.sql
	@echo
	@echo "Schema is at $(SHAREDIR)/schema.sql. Apply it with:"
	@echo "  clickhouse-client < $(SHAREDIR)/schema.sql"
	@echo "Then set CH_ARGS in $(SYSCONFDIR)/default/pping."

install-all:
ifneq ($(shell uname -s),Linux)
	@echo "install-all is Linux-only (needs systemd + setcap + /etc/cron.d)."
	@echo "On macOS/BSD use 'make install' for a binary-only install."
	@exit 1
endif
	$(MAKE) install
	$(MAKE) install-systemd
	$(MAKE) install-clickhouse

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/pping

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping.service
	if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi
	# /etc/default/pping is intentionally left in place

uninstall-clickhouse:
	rm -f $(DESTDIR)$(PREFIX)/bin/pping-load.sh
	rm -f $(DESTDIR)$(SYSCONFDIR)/cron.d/pping-load
	rm -f $(DESTDIR)$(SHAREDIR)/schema.sql
	rmdir --ignore-fail-on-non-empty $(DESTDIR)$(SHAREDIR) 2>/dev/null || true
	# /etc/default/pping and any *.load files are intentionally left in place

uninstall-all: uninstall-clickhouse uninstall-systemd uninstall

.PHONY: install install-systemd install-clickhouse install-all
.PHONY: uninstall uninstall-systemd uninstall-clickhouse uninstall-all
