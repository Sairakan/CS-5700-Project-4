# -*- coding: utf-8 -*-
"""
Authors: Jason Teng, Jae Son
"""




'''
###############################################################################################
REFERENCE CODE
# some imports
import socket, sys
from struct import *

# checksum functions needed for calculation checksum
def checksum(msg):
	s = 0
	
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
		s = s + w
	
	s = (s>>16) + (s & 0xffff);
	s = s + (s >> 16);
	
	#complement and mask to 4 byte short
	s = ~s & 0xffff
	
	return s

#create a raw socket
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
except socket.error , msg:
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()

# tell kernel not to put in headers, since we are providing it, when using IPPROTO_RAW this is not necessary
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	
# now start constructing the packet
packet = '';

source_ip = '192.168.1.101'
dest_ip = '192.168.1.1'	# or socket.gethostbyname('www.google.com')

# ip header fields
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tot_len = 0	# kernel will fill the correct total length
ip_id = 54321	#Id of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = socket.IPPROTO_TCP
ip_check = 0	# kernel will fill the correct checksum
ip_saddr = socket.inet_aton ( source_ip )	#Spoof the source ip address if you want to
ip_daddr = socket.inet_aton ( dest_ip )

ip_ihl_ver = (ip_ver << 4) + ip_ihl

# the ! in the pack format string means network order
ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

# tcp header fields
tcp_source = 1234	# source port
tcp_dest = 80	# destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)	#	maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

# the ! in the pack format string means network order
tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

user_data = 'Hello, how are you'

# pseudo header fields
source_address = socket.inet_aton( source_ip )
dest_address = socket.inet_aton(dest_ip)
placeholder = 0
protocol = socket.IPPROTO_TCP
tcp_length = len(tcp_header) + len(user_data)

psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
psh = psh + tcp_header + user_data;

tcp_check = checksum(psh)
#print tcp_checksum

# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

# final full packet - syn packets dont have any data
packet = ip_header + tcp_header + user_data

#Send the packet finally - the port specified has no effect
s.sendto(packet, (dest_ip , 0 ))	# put this in a loop if you want to flood the target
####################################################################################
'''



from socket import AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_TCP
import socket, argparse, struct, gzip, io, zlib
from base64 import b64decode

parser = argparse.ArgumentParser(description='Client script for Project 4')
parser.add_argument('url', help='URL')

args = parser.parse_args()

url = args.url

sendSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
recSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
recSock.settimeout(180000)

# gets the host ip by creating a connection to Google and observing the socket parameters
hostIP = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

print(hostIP)

hostIP_hex = bytes(map(int, hostIP.split('.')))

# takes a HTTP message and returns the raw header and html as separate strings
def parse_response(response):
    s = response.split(b'\r\n\r\n', 1)
    if len(s) < 2:
        return s[0], ''
    return s[0], s[1]

# takes a string of headers and returns a dictionary of the headers
def parse_headers(rawheaders):
    headers = {}
    rawheaders = rawheaders.splitlines()[1:-1]
    for s in rawheaders:
        header = s.split(': ', 1)
        if header[0] in headers:
            headers[header[0]] = headers.get(header[0]) + '\n' + header[1]
        else:
            headers[header[0]] = header[1]
    return headers

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
ip_daddr = socket.inet_aton('0.0.0.0')

ip_ihl_ver = (ip_ver << 4) + ip_ihl

# the ! in the pack format string means network order
ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)


# tcp header fields
tcp_source = 3306	# source port
tcp_dest = 80	# destination port
tcp_seq = 454
tcp_ack_seq = 0
tcp_doff = 5	#4 bit field, size of tcp header, 5 * 4 = 20 bytes
#tcp flags
tcp_fin = 0
tcp_syn = 1
tcp_rst = 0
tcp_psh = 0
tcp_ack = 0
tcp_urg = 0
tcp_window = socket.htons (5840)	#	maximum allowed window size
tcp_check = 0
tcp_urg_ptr = 0

tcp_offset_res = (tcp_doff << 4) + 0
tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

# the ! in the pack format string means network order
tcp_header = struct.pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)


def tcpwrap(src, dest, seq, ack, flags, awnd, chksm, urg, opt, data):
    """
    Takes in TCP header parameters and creates the correct TCP header and adds it to the data.
    Returns the new message with the TCP header added. Offset is automatically calculated.
    :param src: the source port
    :param dest: the destination port
    :param seq: the sequence number
    :param ack: the acknowledgment number
    :param flags: any flags
    :param awnd: the advertised window
    :param chksm: the checksum to be used
    :param urg: the urgent pointer
    :param opt: any options
    :param data: the data to be wrapped
    :return: the packet wrapped with the TCP header
    """
    offset = 5 + len(opt)/4
    tcp_header = struct.pack('!HHLLBBH', src, dest, seq, ack, offset << 4, flags,  awnd) + struct.pack('H', chksm) + struct.pack('!H', urg) + opt
    tcp_packet = tcp_header + data
    return tcp_packet

def tcpunwrap(tcp_packet):
    """
    Takes a tcp packet and extracts out the header, returning the contained data. Validates the tcp header.
    :param tcp_packet: the packet to be unwrapped
    :return: the unwrapped data
    """
    tcp_header_vals = struct.unpack(tcp_header_format, tcp_packet[0:20])
    tcp_headers = dict(zip(tcp_header_keys, tcp_header_vals))
    # TODO: verify the tcp headers

    # check for options
    offset = tcp_headers['off_res'] >> 4
    print('offset: ' + str(offset))
    if offset > 5:
        options = tcp_packet[20:4*offset]
        print('options: ' + str(options))

    tcp_data = tcp_packet[4*offset:]
    return tcp_data

def ipwrap(version, ihl, tos, tot_len, id, frag_off, ttl, proto, check, src, dest, data):
    """
    Takes in the IP header parameters and constructs a IP header, which is added to the given data and returned.
    :param version: the IP version to use
    :param ihl: the length of the header, in 4-byte words
    :param tos: the Type of Service
    :param tot_len: the total length of the IP packet in bytes (header + data)
    :param id: the ID of the packet
    :param frag_off: the fragment offset
    :param ttl: the time to live of the packet
    :param proto: the protocol of the enclosed packet
    :param check: the checksum to be used (must be pre-calculated)
    :param src: the source IP address
    :param dest: the destination IP address
    :return: the full IP packet
    """
    ver_ihl = (version << 4) + ihl

    return struct.pack(ip_header_format, ver_ihl, tos, tot_len, id, frag_off, ttl, proto, check, src, dest)

def ipunwrap(ip_packet):
    ip_header_vals = struct.unpack(ip_header_format, ip_packet[0:20])
    ip_headers = dict(zip(ip_header_keys, ip_header_vals))
    # TODO: verify the ip header is correct
    version = ip_headers['ver_ihl'] >> 4
    if version != 4:
        return None
    ihl = ip_headers['ver_ihl'] & 0x0F

    # check that this is the destination
    if ip_headers['dest'] != hostIP_hex:
        return None

    # check that is tcp packet
    print('protocol: ' + str(ip_headers['proto']))
    if ip_headers['proto'] != 0x06:
        return None

    print('size of ip packet: ' + str(ip_headers['tot_len']))
    print('ip_id: ' + str(ip_headers['id']))
    # get the data from the ip packet
    ip_data = ip_packet[4*ihl:]
    return ip_data

# Referenced from Suraj Bisht of Bitforestinfo
def checksum(data):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(data), 2):
        if (i+1) < len(data):
            a = ord(data[i]) 
            b = ord(data[i+1])
            s = s + (a+(b << 8))
        elif (i+1)==len(data):
            s += ord(data[i])
        else:
            raise ValueError("Something Wrong here")


    # One's Complement
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

# VERY untested. To be completed later.
def tcp_handshake():
    tcp_seq = 1
    tcp_ack_seq = 0
    
    ip_header = ipwrap(ip_ver, ip_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, 
                       ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    tcp_header = struct.pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, 
                        tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, 
                        tcp_urg_ptr) 
    
    dest_ip = socket.gethostbyname(url)
    source_address = socket.inet_aton( hostIP )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header;
    
    new_check = checksum(psh)
    tcp_header = tcpwrap('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, 
                        tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, 
                        struct.pack('H' , new_check),
                        struct.pack('!H' , tcp_urg_ptr))
    
    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header
    s.sendto(packet, (dest_ip , 0 ))
    
    received = s.recvfrom(1024)
    received_ack = received[3]
    
    if tcp_seq == received_ack - 1:
        tcp_seq = 2
    
        tcp_header = tcpwrap('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, 
                            tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, 
                            struct.pack('H' , new_check),
                            struct.pack('!H' , tcp_urg_ptr))
        packet = ip_header + tcp_header
        s.sendto(packet, (dest_ip, 0))
    else:
        print("Handshake failed!")
#############################################################################

def run():
    # TODO: change the file name based on the given url
    f = open('index.html', 'wb+')

    # TODO: perform TCP handshake, get seq/ack numbers for use in rest of program

    # TODO: send HTTP GET request (maybe can be done at the end of the handshake?)

    # TODO: get the HTTP response (by listening and responding with appropriate acks)
    for i in range(5):
        packet = recSock.recv(65565)
        tcppacket = ipunwrap(packet)
        if tcppacket:
            data = tcpunwrap(tcppacket)
            print(data)
            if len(data) > 0:
                try:
                    rawheaders, rawbody = parse_response(data)
                except UnicodeDecodeError:
                    print('tls packet')
                try:
                    headers = parse_headers(rawheaders.decode())
                    print('headers: ' + str(headers))
                    print('body: ' + str(rawbody))
                    f.write(rawbody)
                except IndexError:
                    print('body: ' + str(rawbody))
        else:
            print('not a tcp packet')

    f.close()

run()
