# should only need to change LIBTINS to the libtins install prefix
# (typically /usr/local unless overridden when tins built)
LIBTINS = $(HOME)/src/libtins
CPPFLAGS += -I$(LIBTINS)/include
LDFLAGS += -L$(LIBTINS)/lib -ltins -lpcap
CXXFLAGS += -std=c++14 -g -O3 -Wall

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

pping:  pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o pping pping.cpp $(LDFLAGS)

check: pping test/unit_tests
	@cd test && sh run_tests.sh

test/unit_tests: test/unit_tests.cpp pping.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o test/unit_tests test/unit_tests.cpp $(LDFLAGS)

clean:
	rm -f pping test/unit_tests
