# -*- coding: utf-8 -*-
"""
Spyder Editor

Authors: Jason Teng, Jae Son
"""

from socket import AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_TCP
import socket, argparse, struct

parser = argparse.ArgumentParser(description='Client script for Project 4')
parser.add_argument('url', help='URL')

args = parser.parse_args()

url = args.url

sendSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
recSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_TCP)

# gets the host ip by creating a connection to Google and observing the socket parameters
hostIP = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

print(hostIP)

for i in range(10):
    packet = recSock.recv(65565)
    print(packet)

"""
Takes in TCP header parameters and creates the correct TCP header and adds it to the data.
Returns the new message with the TCP header added.
PARAMETERS:
src: the source port
dest: the destination port
seq: the sequence number
ack: the acknowledgement number
offset: the offset
flags: any flags
awnd: the advertised window
chksm: the checksum
urg: the urgent pointer
opt: any options
data: the data to be wrapped
RETURNS:
the packet wrapped with the TCP header
"""
def TCPWrapper(src, dest, seq, ack, offset, flags, awnd, chksm, urg, opt, data):
    tcp_header = struct.pack('!HHLLBBHHH', src, dest, seq, ack, offset, flags, awnd, chksm, urg)
    tcp_packet = tcp_header + opt + data
    return tcp_packet
