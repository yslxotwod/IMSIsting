#!/usr/bin/env python3
"""Is anything listening on an SCTP port?

2905 is SCTP. A TCP probe (bash /dev/tcp, nc -z, ss -lt) cannot see an SCTP
listener at all, so a working OsmoSTP looks dead and the lane that depends on it
skips while claiming the network is the problem. This asks the kernel the right
question: connect an SCTP socket and see whether it is accepted.

Usage: ss7_sctp_probe.py <host> <port> [timeout_s]
Exit: 0 listening, 1 refused or timed out, 2 SCTP not available in this kernel.
"""
import socket
import sys


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: ss7_sctp_probe.py <host> <port> [timeout_s]\n")
        return 2
    host, port = argv[1], int(argv[2])
    timeout = float(argv[3]) if len(argv) > 3 else 2.0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132)
    except OSError:
        sys.stderr.write("SCTP is not available in this kernel\n")
        return 2
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except OSError:
        return 1
    finally:
        s.close()
    print("listening")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
