"""Send controlled UDP fixtures to an isolated validation VM."""
import argparse
import socket
import time

parser = argparse.ArgumentParser()
parser.add_argument("host")
parser.add_argument("--seconds", type=float, default=15)
parser.add_argument("--payload-size", type=int, default=128)
parser.add_argument("--rate", type=float, default=25)
args = parser.parse_args()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.monotonic() + args.seconds
sequence = 0
while time.monotonic() < end:
    payload = b"winptap-controlled-frame-" + sequence.to_bytes(4, "big")
    payload += bytes(i % 256 for i in range(args.payload_size))
    sock.sendto(payload, (args.host, 48931))
    sequence += 1
    time.sleep(1 / args.rate)
print(f"Sent {sequence} controlled UDP datagrams")
