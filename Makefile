# should only need to change LIBTINS to the libtins install prefix
# (typically /usr/local unless overridden when tins built)
LIBTINS = $(HOME)/src/libtins
CPPFLAGS += -I$(LIBTINS)/include
CPPFLAGS += -Ithird_party
LDFLAGS += -L$(LIBTINS)/lib -ltins -lpcap
CXXFLAGS += -std=c++17 -g -O3 -Wall -flto=auto
LDFLAGS  += -flto=auto

# Reproducible version string: exact tag → "1.1.1"; off-tag → "1.1.1-3-gSHA";
# dirty tree → "...-dirty"; tarball (no .git) → VERSION file; neither → unknown.
# git -C $(CURDIR) so `make -C path/to/pping2` from elsewhere still resolves
# the repo's git state, not make's invocation cwd.
# Group the fallback chain BEFORE `sed`. Without the braces, `git describe`'s
# failure feeds an empty stream into `sed`, which succeeds (exit 0) and masks
# the `||` fallbacks — producing an empty version string on shallow CI clones
# without tags. The grouped form lets the fallbacks resolve first, then `sed`
# strips the optional leading `v`.
VERSION := $(shell { git -C $(CURDIR) describe --tags --dirty --match 'v*' 2>/dev/null \
                     || cat $(CURDIR)/VERSION 2>/dev/null \
                     || echo unknown; } | sed 's/^v//')
CPPFLAGS += -DPPING_VERSION=\"$(VERSION)\"

# CRC32C hardware hash requires SSE4.2 (included in x86-64-v3) on amd64, and
# the CRC extension on aarch64. GCC's default -march=armv8-a does NOT enable
# CRC32 even though the ARMv8.0-A spec mandates it — +crc opts into the
# extension explicitly so __crc32cd from <arm_acle.h> is callable.
# GCC's "last -march wins" rule: users who append -march=native or -march=znver3
# via CXXFLAGS override this intentionally; packagers targeting a lower baseline
# should edit this line or set PPING_MARCH in a wrapper (YAGNI for now).
ifeq ($(shell uname -m),x86_64)
CXXFLAGS += -march=x86-64-v3
endif
ifeq ($(shell uname -m),aarch64)
CXXFLAGS += -march=armv8-a+crc
endif

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

# STATIC=1 builds a fully self-contained binary — no shared library deps
# and no dynamic linker reference baked into PT_INTERP. Use with a musl
# toolchain (Alpine container, muslcc.cc cross-toolchain) plus libtins and
# libpcap built as static archives. Target use case: drop-in deployment
# on OpenWrt and other musl systems whose loader path
# (/lib/ld-musl-*.so.1) differs from glibc's (/lib/ld-linux-*.so.1).
#
# -static and -pie are practically incompatible; -static-pie exists but
# requires PIE-aware static libs (libtins) and is fragile across
# toolchains. Drop PIE for static builds and keep the rest of the
# hardening (relro/now/noexecstack, stack-protector, _FORTIFY_SOURCE).
# This block must come AFTER the -pie/-fPIE appends so filter-out has
# something to remove.
ifeq ($(STATIC),1)
CXXFLAGS := $(filter-out -fPIE,$(CXXFLAGS))
LDFLAGS  := $(filter-out -pie,$(LDFLAGS))
LDFLAGS  += -static -static-libstdc++ -static-libgcc
endif

# --- Install paths and packaging variables ---
PREFIX      ?= /usr/local
SYSCONFDIR  ?= /etc
SHAREDIR    ?= $(PREFIX)/share/pping2
DESTDIR     ?=
_DESTDIR_EMPTY = $(if $(strip $(DESTDIR)),,1)

pping2:  pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o pping2 pping.cpp $(LDFLAGS)

check: pping2 test/unit_tests
	@cd test && sh run_tests.sh

test: check

test/unit_tests: test/unit_tests.cpp pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o test/unit_tests test/unit_tests.cpp $(LDFLAGS)

clean:
	rm -f pping2 test/unit_tests
	rm -rf pgo-data

bench: pping2
	@mkdir -p docs/superpowers/baselines
	@./test/bench.sh | tee "docs/superpowers/baselines/$$(date -u +%Y-%m-%d)-bench-$$(git rev-parse --short HEAD).txt"

# Profile-Guided Optimization. Two-phase: build an instrumented binary, run it
# over a representative pcap to gather branch/edge counts, then rebuild using
# that profile so GCC lays out the hot per-packet dispatch optimally.
#
# Training input resolves like test/bench.sh: $BENCH_PCAP, then ~/bench.pcap.
# Refuses to train on the tiny synth fixtures — a profile gathered from a few
# hundred packets would mis-train branch layout. Supply a 1M+ pcap with
# realistic flow churn (the same input you bench with).
#
# Usage:
#   make pgo                              # uses ~/bench.pcap
#   BENCH_PCAP=/path/to/big.pcap make pgo
#
# The profile is gathered across all three modes so neither the TS nor the SEQ
# hot path is starved of training data. -fprofile-correction tolerates the
# slightly inconsistent counts that result from multiple training runs.
PGO_DIR := pgo-data
PGO_PCAP := $(or $(BENCH_PCAP),$(HOME)/bench.pcap)

.PHONY: pgo
pgo:
	@test -f "$(PGO_PCAP)" || { \
	    echo "ERROR: no training pcap at '$(PGO_PCAP)'."; \
	    echo "Set BENCH_PCAP=/path/to/big.pcap (1M+ packets, realistic flow churn)."; \
	    exit 1; }
	@echo "PGO phase 1/2: building instrumented binary"
	rm -rf $(PGO_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fprofile-generate=$(PGO_DIR) \
	    -o pping2 pping.cpp $(LDFLAGS)
	@echo "PGO phase 1/2: gathering profile from $(PGO_PCAP)"
	./pping2 -q --mode hybrid -a -r "$(PGO_PCAP)" >/dev/null
	./pping2 -q --mode ts     -m -r "$(PGO_PCAP)" >/dev/null
	./pping2 -q --mode seq    -m -r "$(PGO_PCAP)" >/dev/null
	@echo "PGO phase 2/2: rebuilding with profile"
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -fprofile-use=$(PGO_DIR) -fprofile-correction \
	    -o pping2 pping.cpp $(LDFLAGS)
	@echo "PGO build complete. Profile data in $(PGO_DIR)/ (gitignored)."

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

.PHONY: check-install-vars
check-install-vars:
	@test -n "$(PREFIX)"     || { echo "ERROR: PREFIX is empty";     exit 1; }
	@test -n "$(SYSCONFDIR)" || { echo "ERROR: SYSCONFDIR is empty"; exit 1; }

# install does not depend on the build target so that pre-built binary
# (tar.gz release) users can run `make install-all` without needing the
# source or libtins. Source users: `make pping2 && sudo make install-all`.
install: check-install-vars
	@test -f pping2 || { echo "Build first: make pping2"; exit 1; }
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 pping2 $(DESTDIR)$(PREFIX)/bin/pping2
ifeq ($(shell uname -s),Linux)
ifneq ($(_DESTDIR_EMPTY),)
	setcap cap_net_raw+ep $(PREFIX)/bin/pping2
else
	@echo ""
	@echo "WARNING: setcap skipped because DESTDIR is set."
	@echo "Apply in your packaging postinst (or run manually):"
	@echo "  setcap cap_net_raw+ep $(PREFIX)/bin/pping2"
endif
endif

install-systemd: check-install-vars
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
	# The unit runs as a dedicated `pping2` system user (not the shared
	# `nobody` UID — systemd warns on that, and it collides with NFS's
	# anonymous UID and any other service also confined to `nobody`).
	if [ -z "$(DESTDIR)" ]; then \
	    if ! getent passwd pping2 >/dev/null; then \
	        adduser --system --group --no-create-home \
	            --shell /usr/sbin/nologin pping2; \
	    fi; \
	else \
	    echo ""; \
	    echo "WARNING: user creation skipped because DESTDIR is set."; \
	    echo "Apply in your packaging postinst (or run manually):"; \
	    echo '  adduser --system --group --no-create-home --shell /usr/sbin/nologin pping2'; \
	fi
	install -d $(DESTDIR)/var/log/pping2
	if [ -z "$(DESTDIR)" ]; then \
	    chown pping2:pping2 /var/log/pping2; \
	    systemctl daemon-reload; \
	else \
	    echo ""; \
	    echo "WARNING: chown skipped because DESTDIR is set."; \
	    echo "Apply in your packaging postinst (or run manually):"; \
	    echo '  chown pping2:pping2 /var/log/pping2'; \
	fi
	@echo
	@echo "Edit $(SYSCONFDIR)/default/pping2 (set PPING_IFACE), then:"
	@echo "  sudo systemctl enable --now pping2"

install-clickhouse: check-install-vars
	install -d $(DESTDIR)$(PREFIX)/bin
	$(SUBST) contrib/clickhouse/pping2-load.sh \
	    > $(DESTDIR)$(PREFIX)/bin/pping2-load.sh
	chmod 0755 $(DESTDIR)$(PREFIX)/bin/pping2-load.sh
	install -d $(DESTDIR)$(SYSCONFDIR)/systemd/system
	$(SUBST) contrib/clickhouse/pping2-load.service \
	    > $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2-load.service
	chmod 0644 $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2-load.service
	install -m 0644 contrib/clickhouse/pping2-load.timer \
	    $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2-load.timer
	# Earlier installs scheduled the loader from cron; drop the stale entry
	# so both schedulers don't fire.
	rm -f $(DESTDIR)$(SYSCONFDIR)/cron.d/pping2-load
	if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi
	install -d $(DESTDIR)$(SHAREDIR)
	install -m 0644 contrib/clickhouse/schema.sql \
	    $(DESTDIR)$(SHAREDIR)/schema.sql
	install -m 0644 contrib/clickhouse/ingest-user.sql \
	    $(DESTDIR)$(SHAREDIR)/ingest-user.sql
	@echo
	@echo "Schema is at $(SHAREDIR)/schema.sql. Apply it with:"
	@echo "  clickhouse-client < $(SHAREDIR)/schema.sql"
	@echo "Write-only loader user is at $(SHAREDIR)/ingest-user.sql."
	@echo "Edit the password, then apply it the same way."
	@echo "Then set CH_ARGS in $(SYSCONFDIR)/default/pping2 and start the loader:"
	@echo "  sudo systemctl enable --now pping2-load.timer"

install-all: check-install-vars
ifneq ($(shell uname -s),Linux)
	@echo "install-all is Linux-only (needs systemd + setcap)."
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
	if [ -z "$(DESTDIR)" ]; then \
	    systemctl disable --now pping2-load.timer 2>/dev/null || true; \
	fi
	rm -f $(DESTDIR)$(PREFIX)/bin/pping2-load.sh
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2-load.service
	rm -f $(DESTDIR)$(SYSCONFDIR)/systemd/system/pping2-load.timer
	# stale cron entry from pre-timer installs
	rm -f $(DESTDIR)$(SYSCONFDIR)/cron.d/pping2-load
	rm -f $(DESTDIR)$(SHAREDIR)/schema.sql
	rm -f $(DESTDIR)$(SHAREDIR)/ingest-user.sql
	rmdir --ignore-fail-on-non-empty $(DESTDIR)$(SHAREDIR) 2>/dev/null || true
	if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi
	# /etc/default/pping2 and any *.load files are intentionally left in place

uninstall-all: uninstall-clickhouse uninstall-systemd uninstall

.PHONY: test check clean pcaps bench
.PHONY: check-install-vars install install-systemd install-clickhouse install-all
.PHONY: uninstall uninstall-systemd uninstall-clickhouse uninstall-all
