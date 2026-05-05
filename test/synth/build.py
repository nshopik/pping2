"""Run all pcap-synth modules and write outputs to test/pcaps/."""
from . import common, dns_tcp_linux


def main():
    common.write("dns-tcp-linux.pcap", dns_tcp_linux.build())
    # dns_tcp_windows and mixed_with_retx added in Tasks 6 and 7.


if __name__ == "__main__":
    main()
