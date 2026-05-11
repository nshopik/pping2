# should only need to change LIBTINS to the libtins install prefix
# (typically /usr/local unless overridden when tins built)
LIBTINS = $(HOME)/src/libtins
CPPFLAGS += -I$(LIBTINS)/include
LDFLAGS += -L$(LIBTINS)/lib -ltins -lpcap
CXXFLAGS += -std=c++17 -g -O3 -Wall

# Hardening: pping2 runs as root briefly to open the packet socket and
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
SHAREDIR    ?= $(PREFIX)/share/pping2
DESTDIR     ?=

pping2:  pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o pping2 pping.cpp $(LDFLAGS)

check: pping2 test/unit_tests
	@cd test && sh run_tests.sh

test: check

test/unit_tests: test/unit_tests.cpp pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o test/unit_tests test/unit_tests.cpp $(LDFLAGS)

clean:
	rm -f pping2 test/unit_tests

bench: pping2
	@mkdir -p docs/superpowers/baselines
	@./test/bench.sh | tee "docs/superpowers/baselines/$$(date -u +%Y-%m-%d)-bench-$$(git rev-parse --short HEAD).txt"

# Regenerate test fixtures from test/synth/. Requires scapy.
pcaps:
	cd test && python3 -m synth.build

# Path substitution applied at install time so the shipped contrib/ scripts
# work under arbitrary PREFIX/SYSCONFDIR. Source files keep /usr/local/bin
# and /etc/default literals so they remain runnable from a checkout.
SUBST = sed \
    -e "s|/usr/local/bin|$(PREFIX)/bin|g" \
    -e "s|/etc/default/pping2|$(SYSCONFDIR)/default/pping2|g"

# --- Install / uninstall ---

# install does not depend on the build target so that pre-built binary
# (tar.gz release) users can run `make install-all` without needing the
# source or libtins. Source users: `make pping2 && sudo make install-all`.
install:
	@test -f pping2 || { echo "Build first: make pping2"; exit 1; }
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 pping2 $(DESTDIR)$(PREFIX)/bin/pping2
ifeq ($(shell uname -s),Linux)
	if [ -z "$(DESTDIR)" ]; then \
	    setcap cap_net_raw+ep $(PREFIX)/bin/pping2; \
	else \
	    echo ""; \
	    echo "WARNING: setcap skipped because DESTDIR is set."; \
	    echo "Apply in your packaging postinst (or run manually):"; \
	    echo "  setcap cap_net_raw+ep $(PREFIX)/bin/pping2"; \
	fi
endif

install-systemd:
	install -d $(DESTDIR)$(SYSCONFDIR)/systemd/system
	$(SUBST) contrib/systemd/pping2.service \
	    > $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2.service
	chmod 0644 $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2.service
	install -d $(DESTDIR)$(SYSCONFDIR)/default
	# 0640: this file holds the ClickHouse loader's CH_AUTH / CH_ARGS,
	# which may contain credentials. World-readable would leak them to
	# every local user. The Debian postinst also `chmod o-rwx`es it on
	# upgrade so installs that came from pre-hardening packages get fixed.
	if [ ! -e $(DESTDIR)$(SYSCONFDIR)/default/pping2 ] \
	   && [ ! -L $(DESTDIR)$(SYSCONFDIR)/default/pping2 ]; then \
	    install -m 0640 contrib/systemd/pping2.default \
	        $(DESTDIR)$(SYSCONFDIR)/default/pping2; \
	fi
	# pping2 drops to `nobody` after opening the packet socket, so it
	# needs a directory it can recreate the logfile in on SIGHUP.
	install -d $(DESTDIR)/var/log/pping2
	if [ -z "$(DESTDIR)" ]; then \
	    chown nobody:`id -gn nobody` /var/log/pping2; \
	    systemctl daemon-reload; \
	else \
	    echo ""; \
	    echo "WARNING: chown skipped because DESTDIR is set."; \
	    echo "Apply in your packaging postinst (or run manually):"; \
	    echo '  chown nobody:$$(id -gn nobody) /var/log/pping2'; \
	fi
	@echo
	@echo "Edit $(SYSCONFDIR)/default/pping2 (set PPING_IFACE), then:"
	@echo "  sudo systemctl enable --now pping2"

install-clickhouse:
	install -d $(DESTDIR)$(PREFIX)/bin
	$(SUBST) contrib/clickhouse/pping2-load.sh \
	    > $(DESTDIR)$(PREFIX)/bin/pping2-load.sh
	chmod 0755 $(DESTDIR)$(PREFIX)/bin/pping2-load.sh
	install -d $(DESTDIR)$(SYSCONFDIR)/cron.d
	$(SUBST) contrib/clickhouse/pping2-load.cron \
	    > $(DESTDIR)$(SYSCONFDIR)/cron.d/pping2-load
	chmod 0644 $(DESTDIR)$(SYSCONFDIR)/cron.d/pping2-load
	install -d $(DESTDIR)$(SHAREDIR)
	install -m 0644 contrib/clickhouse/schema.sql \
	    $(DESTDIR)$(SHAREDIR)/schema.sql
	@echo
	@echo "Schema is at $(SHAREDIR)/schema.sql. Apply it with:"
	@echo "  clickhouse-client < $(SHAREDIR)/schema.sql"
	@echo "Then set CH_ARGS in $(SYSCONFDIR)/default/pping2."

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
	rm -f $(DESTDIR)$(PREFIX)/bin/pping2

uninstall-systemd:
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2.service
	if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi
	# /etc/default/pping2 and /var/log/pping2/ are intentionally left in place

uninstall-clickhouse:
	rm -f $(DESTDIR)$(PREFIX)/bin/pping2-load.sh
	rm -f $(DESTDIR)$(SYSCONFDIR)/cron.d/pping2-load
	rm -f $(DESTDIR)$(SHAREDIR)/schema.sql
	rmdir --ignore-fail-on-non-empty $(DESTDIR)$(SHAREDIR) 2>/dev/null || true
	# /etc/default/pping2 and any *.load files are intentionally left in place

uninstall-all: uninstall-clickhouse uninstall-systemd uninstall

.PHONY: test check clean pcaps bench
.PHONY: install install-systemd install-clickhouse install-all
.PHONY: uninstall uninstall-systemd uninstall-clickhouse uninstall-all
