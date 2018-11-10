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

ip_header_format = '!BBHHHBBH4s4s'
tcp_header_format = '!HHLLBBHHH'

# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0  # kernel will fill the correct total length
ip_id = 54321   # Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0    # kernel will fill the correct checksum
ip_saddr = socket.inet_aton(hostIP)
ip_daddr = socket.inet_aton('8.8.8.8')

ip_ihl_ver = (ip_ver << 4) + ip_ihl

# the ! in the pack format string means network order
ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

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
def tcpwrapper(src, dest, seq, ack, offset, flags, awnd, chksm, urg, opt, data):
    tcp_header = struct.pack(tcp_header_format, src, dest, seq, ack, offset, flags, awnd, chksm, urg)
    tcp_packet = tcp_header + opt + data
    return tcp_packet

def tcpunwrap(tcp_packet):
    tcp_header = struct.unpack(tcp_header_format, tcp_packet[0:20])
    tcp_data = tcp_packet[struct.calcsize(tcp_header_format):]
    return tcp_data

def ipunwrap(ip_packet):
    ip_header = struct.unpack(ip_header_format, ip_packet[0:20])
    # verify the ip header is correct
    # get the data from the ip packet
    ip_data = ip_packet[struct.calcsize(ip_header_format):]
    return ip_data


for i in range(2):
    packet = recSock.recv(65565)
    data = tcpunwrap(ipunwrap(packet))
    print(data)
    print(data.decode() + '\n')
