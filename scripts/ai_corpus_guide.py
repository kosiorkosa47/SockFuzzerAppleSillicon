#!/usr/bin/env python3
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# AI-guided corpus selection (#90)
#
# Analyzes coverage gaps and generates targeted fuzzing seeds.
# Uses coverage report to identify uncovered functions, then
# reasons about what inputs would reach them.
#
# Usage:
#   python3 scripts/ai_corpus_guide.py <coverage_report> [--output seeds/]
#
# Input: llvm-cov report output (text format)
# Output: analysis with recommended proto field values

import sys
import os
import re
import json
from collections import defaultdict

# Map XNU source files to proto commands that exercise them
FILE_TO_COMMANDS = {
    "tcp_input.c": ["TcpPacket", "Tcp6Packet", "TcpSession"],
    "tcp_output.c": ["Sendmsg", "Sendto", "Connect"],
    "tcp_subr.c": ["Socket(SOCK_STREAM)", "Close", "Shutdown"],
    "tcp_timer.c": ["ClearAll (timer drain)"],
    "tcp_usrreq.c": ["Socket", "Bind", "Listen", "Accept", "Connect"],
    "tcp_sack.c": ["TcpPacket with SACK option"],
    "udp_usrreq.c": ["UdpPacket", "Socket(SOCK_DGRAM)", "Sendto"],
    "udp6_usrreq.c": ["Udp6Packet", "Socket(AF_INET6, SOCK_DGRAM)"],
    "ip_input.c": ["Ip4Packet", "TcpPacket", "UdpPacket", "Icmp4Packet"],
    "ip_output.c": ["Sendmsg", "Sendto", "Connect"],
    "ip6_input.c": ["Ip6Packet", "Tcp6Packet", "Udp6Packet", "Icmp6Packet"],
    "ip_icmp.c": ["Icmp4Packet"],
    "icmp6.c": ["Icmp6Packet"],
    "frag6.c": ["Ip6Packet with FragHdr extension"],
    "route6.c": ["Ip6Packet with RtHdr extension"],
    "pf.c": ["PfControl", "IoctlReal(DIOC*)"],
    "pf_ioctl.c": ["PfControl", "IoctlReal(DIOC*)"],
    "necp.c": ["NecpOpen", "NecpSessionAction", "NecpMatchPolicy"],
    "necp_client.c": ["NecpClientAction"],
    "content_filter.c": ["ContentFilterAttach", "Socket(AF_SYSTEM)"],
    "flow_divert.c": ["FlowDivertConnect", "Socket(AF_SYSTEM)"],
    "uipc_socket.c": ["Socket", "Bind", "Listen", "Accept", "Close"],
    "uipc_usrreq.c": ["Socket(AF_UNIX)", "SockAddrUn"],
    "kern_event.c": ["Kqueue"],
    "mptcp.c": ["MptcpSocket", "MptcpSetsockopt"],
    "in_pcb.c": ["Bind", "Connect", "Listen"],
    "if_loop.c": ["Packet injection (lo0)"],
    "if_bridge.c": ["IoctlReal (bridge ioctls)"],
    "if_vlan.c": ["IoctlReal (VLAN ioctls)"],
    "key.c": ["IPsec key management (not yet fuzzed)"],
}

# Suggested proto field values for reaching specific functions
FUNCTION_HINTS = {
    "tcp_do_segment": "Send TcpPacket with SYN flag to a listening socket",
    "tcp_respond": "Send RST to an established connection",
    "tcp_close": "Use TcpSession(TCP_CLOSE_WAIT) or Shutdown",
    "tcp_timewait": "Use TcpSession(TCP_TIME_WAIT)",
    "ip_dooptions": "Set IpHdr.ip_options with LSRR/SSRR/timestamp bytes",
    "frag6_input": "Send Ip6Packet with Ip6FragHdr extension header",
    "nd6_na_input": "Send Icmp6Packet with type=136 (Neighbor Advertisement)",
    "pf_test_rule": "Use PfControl(PF_START) then send packets",
    "cfil_sock_attach": "Use ContentFilterAttach on a TCP socket",
    "flow_divert_connect": "Use FlowDivertConnect with a target address",
    "mptcp_subflow_add": "Create MptcpSocket then connect to address",
    "soconnect": "Use Connect with a valid SockAddr",
    "sosend_dgram": "Use Sendto on a UDP socket",
    "soreceive_dgram": "Use Recvfrom on a bound UDP socket after sending data",
}


def parse_coverage_report(report_file):
    """Parse llvm-cov report and extract uncovered functions."""
    uncovered = []
    covered = []

    with open(report_file) as f:
        for line in f:
            # llvm-cov report format: filename | regions | miss | cover% | ...
            match = re.match(r'\s*(.+\.c)\s+\|\s+(\d+)\s+(\d+)\s+([\d.]+)%', line)
            if match:
                filename = match.group(1).strip()
                regions = int(match.group(2))
                missed = int(match.group(3))
                coverage = float(match.group(4))

                entry = {
                    "file": os.path.basename(filename),
                    "regions": regions,
                    "missed": missed,
                    "coverage": coverage,
                }

                if coverage < 50.0:
                    uncovered.append(entry)
                else:
                    covered.append(entry)

    return sorted(uncovered, key=lambda x: x["coverage"]), covered


def generate_recommendations(uncovered):
    """Generate fuzzing recommendations for uncovered files."""
    recommendations = []

    for entry in uncovered:
        fname = entry["file"]
        rec = {
            "file": fname,
            "coverage": entry["coverage"],
            "missed_regions": entry["missed"],
            "commands": FILE_TO_COMMANDS.get(fname, ["Unknown — needs investigation"]),
            "hints": [],
        }

        # Add function-specific hints
        for func, hint in FUNCTION_HINTS.items():
            if any(cmd_prefix in fname.lower() for cmd_prefix in
                   func.split("_")[:2]):
                rec["hints"].append(f"{func}: {hint}")

        recommendations.append(rec)

    return recommendations


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <coverage_report> [--output dir/]")
        print()
        print("Without a coverage report, prints the function→command mapping:")
        print()
        for func, hint in sorted(FUNCTION_HINTS.items()):
            print(f"  {func:30s} → {hint}")
        sys.exit(0)

    report_file = sys.argv[1]
    output_dir = "coverage_recommendations"
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_dir = sys.argv[idx + 1]

    if not os.path.exists(report_file):
        print(f"Error: {report_file} not found")
        sys.exit(1)

    uncovered, covered = parse_coverage_report(report_file)

    print(f"=== AI Corpus Guide ===")
    print(f"Covered files (>50%):   {len(covered)}")
    print(f"Uncovered files (<50%): {len(uncovered)}")
    print()

    recommendations = generate_recommendations(uncovered)

    print("=== Top 10 Uncovered Files ===")
    for rec in recommendations[:10]:
        print(f"\n  {rec['file']} ({rec['coverage']:.1f}% covered, "
              f"{rec['missed_regions']} regions missed)")
        print(f"  Commands to try: {', '.join(rec['commands'])}")
        for hint in rec["hints"][:3]:
            print(f"    Hint: {hint}")

    # Save recommendations
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "recommendations.json")
    with open(output_file, "w") as f:
        json.dump(recommendations, f, indent=2)
    print(f"\nFull recommendations saved to: {output_file}")


if __name__ == "__main__":
    main()
