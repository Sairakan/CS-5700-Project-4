# -*- coding: utf-8 -*-
"""
Authors: Jason Teng, Jae Son
"""
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_TCP
import socket, argparse, gzip, io, zlib, random
from base64 import b64decode
from struct import pack, unpack

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
pseudo_header_format = '4s4sBBH'

# These should be constant for the whole program, while sending packets
# TCP Side
SRC_PORT = random.randint(1024, 65530)
DEST_PORT = 80
URG = 0
AWND = socket.htons(1500) # MTU of ethernet

# IP Side
VERSION = 4
IHL = 5
IHL_VERSION = (VERSION << 4) + IHL
TOS = 0
FRAG_OFF = 0
IP_HDR_LEN = 20
TTL = 255
PROTO = socket.IPPROTO_TCP
SRC_ADDR = socket.inet_aton(hostIP)

def tcpwrap(destAddr, seq, ack, flags, opt, data):
    """
    Takes in TCP header parameters and creates the correct TCP header and adds it to the data.
    Returns the new message with the TCP header added. Offset is automatically calculated.
    :param destAddr: destination address
    :param seq: the sequence number of the current packet. += 1 beforehand.
    :param ack: the acknowledgment number
    :param flags: any flags
    :param opt: any options
    :param data: the data to be wrapped
    :return: the packet wrapped with the TCP header
    """
    
    # Create pseudo-header to calculate checksum
    offset = 5 + len(opt)/4
    temp_header = pack(tcp_header_format, SRC_PORT, DEST_PORT, seq, ack, offset << 4, 
                      flags,  AWND, URG)
    total_len = len(temp_header) + len(data)
    pseudo_header = pack(pseudo_header_format , SRC_ADDR , destAddr, 0, PROTO, total_len);
    check = checksum(temp_header + pseudo_header + data)
    
    tcp_header = pack(tcp_header_format , SRC_PORT, DEST_PORT, seq, ack, offset, flags,  
                      AWND) + pack('H' , check) + pack('!H' , URG)
    tcp_packet = tcp_header + data
    return tcp_packet

def tcpunwrap(tcp_packet):
    """
    Takes a tcp packet and extracts out the header, returning the contained data. Validates the 
    :param tcp_packet: the packet to be unwrappedtcp header.
    :return: the unwrapped data
    """
    tcp_header_vals = unpack(tcp_header_format, tcp_packet[0:20])
    tcp_headers = dict(zip(tcp_header_keys, tcp_header_vals))

    # check for options
    offset = tcp_headers['off_res'] >> 4
    print('offset: ' + str(offset))
    if offset > 5:
        options = tcp_packet[20:4*offset]
        print('options: ' + str(options))

    tcp_data = tcp_packet[4*offset:]
    
    if tcp_verify_checksum(tcp_header_vals, options, tcp_data):
        return tcp_data
    else:
        #TCP HEADER OR DATA CHECKSUM HAS FAILED. TODO
        print ('checksum has failed. replicate TCP ACK behavior')

def ipwrap(dest_addr, tcp_packet):
    """
    Takes in the IP header parameters and constructs a IP header, which is added to the given data and returned.
    :param dest_addr: the destination IP address
    :param tcp_packet: the full packet given out by tcpwrap, including payload
    :return: the full IP packet, including the TCP packet
    """
    check = 0 # kernel will fill correct checksum
    pktId = random.randint(0, 65534)
    total_len = len(tcp_packet) + 20
    return pack(ip_header_format, IHL_VERSION, TOS, total_len, pktId, FRAG_OFF, 
                TTL, PROTO, check, SRC_ADDR, dest_addr) + tcp_packet

def ipunwrap(ip_packet):
    ip_header_vals = unpack(ip_header_format, ip_packet[0:20])
    ip_headers = dict(zip(ip_header_keys, ip_header_vals))
    
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
    
    if (ip_verify_checksum(ip_header_vals)):
        return ip_data
    else:
        #IP HEADER CHECKSUM HAS FAILED. TODO
        print ('checksum has failed. replicate TCP ACK behavior')

# Referenced from Suraj Bisht of Bitforestinfo
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = ord(msg[i]) 
            b = ord(msg[i+1])
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += ord(msg[i])
        else:
            raise ValueError("Something Wrong here")


    # One's Complement
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def tcp_verify_checksum(headerVals, opt, data):
    checksum = headerVals[7]
    headerAndData = pack(tcp_header_format, headerVals[0],headerVals[1],headerVals[2],headerVals[3],headerVals[4],
            headerVals[5], headerVals[6], headerVals[7], headerVals[8], opt, data)
    calculatedChecksum = checksum(headerAndData)
    return (calculatedChecksum == checksum)
    
def ip_verify_checksum(headerVals):
    checksum = headerVals[7]
    ipHeader = pack(ip_header_format, headerVals[0],headerVals[1],headerVals[2],headerVals[3],headerVals[4],
            headerVals[5], headerVals[6], headerVals[7], headerVals[8], headerVals[9])
    calculatedChecksum = checksum(ipHeader)
    return (calculatedChecksum == checksum)
    
# VERY untested. To be completed later.
# Re-implement using sendPacket function
def tcp_handshake():
    '''
    
    tcp_seq = 1
    tcp_ack_seq = 0
    
    ip_header = ipwrap(ip_ver, ip_ihl, ip_tos, ip_tot_len, ip_id, ip_frag_off, 
                       ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, 
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
    '''
        
def change_file_name(myUrl):
    fileName = ''
    if myUrl.startswith('http://'):
        myUrl = myUrl[7:]
    elif myUrl.startswith('https://'):
        myUrl = myUrl[8:]
        
    lastSlashIndex = myUrl.rfind('/')
    if lastSlashIndex == -1:
        fileName = 'index.html'
    else:
        if lastSlashIndex == len(myUrl) - 1:
            fileName = 'index.html'
        else:
            fileName = myUrl[lastSlashIndex + 1:]
    return fileName

def sendPacket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.bind(("", "63798"))
    except socket.error:
        print ('Socket creation failed!')
        exit(0)
    
    packet = ''; 
    source_ip = '172.16.87.84'
    dest_ip = '172.16.10.1'
    
    # ip header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton ( source_ip )
    ip_daddr = socket.inet_aton ( dest_ip ) 
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    
    # tcp header fields
    tcp_source = 63798   # source port
    tcp_dest = 8888   # destination port
    tcp_seq = 104
    tcp_ack_seq = 0
    tcp_doff = 5    #4 bit size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
    
    tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr) 
    
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header;
    
    tcp_check = checksum(psh)
    
    tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
    
    packet = ip_header + tcp_header
    s.sendto(packet, (dest_ip , 8888 ))
#############################################################################

def run():
    fileName = change_file_name(url)
        
    f = open(fileName, 'wb+')

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
