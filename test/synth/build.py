"""Run all pcap-synth modules and write outputs to test/pcaps/."""
from . import (
    common,
    dns_tcp_linux,
    dns_tcp_windows,
    mixed_with_retx,
    age_cap,
    idle,
    no_synack,
)


def main():
    common.write("dns-tcp-linux.pcap",   dns_tcp_linux.build())
    common.write("dns-tcp-windows.pcap", dns_tcp_windows.build())
    common.write("mixed-with-retx.pcap", mixed_with_retx.build())
    common.write("age_cap.pcap",         age_cap.build())
    common.write("idle.pcap",            idle.build())
    common.write("no_synack.pcap",       no_synack.build())


if __name__ == "__main__":
    main()
