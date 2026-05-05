"""Run all pcap-synth modules and write outputs to test/pcaps/."""
from . import common, dns_tcp_linux, dns_tcp_windows


def main():
    common.write("dns-tcp-linux.pcap",   dns_tcp_linux.build())
    common.write("dns-tcp-windows.pcap", dns_tcp_windows.build())


if __name__ == "__main__":
    main()
