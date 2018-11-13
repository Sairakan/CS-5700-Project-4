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

hostIP_hex = bytes(map(int, hostIP.split('.')))

ip_header_format = '!BBHHHBBH4s4s'
ip_header_keys = ['ver_ihl', 'tos', 'tot_len', 'id', 'frag_off', 'ttl', 'proto', 'check', 'src', 'dest']
tcp_header_format = '!HHLLBBHHH'
tcp_header_keys = ['src', 'dest', 'seq', 'ack', 'off_res', 'flags', 'awnd', 'chksm', 'urg']

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

def tcpwrapper(src, dest, seq, ack, offset, flags, awnd, chksm, urg, opt, data):
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
    tcp_header = struct.pack(tcp_header_format, src, dest, seq, ack, offset, flags, awnd, chksm, urg)
    tcp_packet = tcp_header + opt + data
    return tcp_packet

def tcpunwrap(tcp_packet):
    tcp_header_vals = struct.unpack(tcp_header_format, tcp_packet[0:20])
    tcp_headers = dict(zip(tcp_header_keys, tcp_header_vals))
    # verify the tcp headers
    # check for options
    offset = tcp_headers['off_res'] >> 4
    print('offset: ' + str(offset))
    if offset > 5:
        options = tcp_packet[20:4*offset]
        print('options: ' + str(options))

    tcp_data = tcp_packet[4*offset:]
    return tcp_data

def ipwrap(version, ihl, tos, tot_len, id, frag_off, ttl, proto, check, src, dest):
    ver_ihl = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack(ip_header_format, ver_ihl, tos, tot_len, id, frag_off, ttl, proto, check, src, dest)

def ipunwrap(ip_packet):
    ip_header_vals = struct.unpack(ip_header_format, ip_packet[0:20])
    ip_headers = dict(zip(ip_header_keys, ip_header_vals))
    # verify the ip header is correct

    ihl = ip_headers['ver_ihl'] & 0xF
    print('ihl: ' + str(ihl))


    # check that this is the destination
    if ip_headers['dest'] != hostIP_hex:
        return None

    # check that is tcp packet
    if ip_headers['proto'] != 0x06:
        return None

    print('size of ip packet: ' + str(ip_headers['tot_len']))
    # get the data from the ip packet
    ip_data = ip_packet[4*ihl:]
    return ip_data


for i in range(10):
    packet = recSock.recv(65565)
    tcppacket = ipunwrap(packet)
    if tcppacket:
        data = tcpunwrap(tcppacket)
        print(data)
    else:
        print('not a tcp packet')
