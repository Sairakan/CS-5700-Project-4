# -*- coding: utf-8 -*-
"""
Authors: Jason Teng, Jae Son
"""
from socket import AF_INET, SOCK_RAW, IPPROTO_RAW, IPPROTO_TCP
import socket, argparse, random, time
from struct import pack, unpack

parser = argparse.ArgumentParser(description='Client script for Project 4')
parser.add_argument('url', help='URL')

args = parser.parse_args()

url = args.url

sendSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
recSock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
TIMEOUT = 3
recSock.settimeout(TIMEOUT)

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
tcp_temp_header_format = '!HHLLBBHHH'
tcp_header_format = '!HHLLBBH'
tcp_header_keys = ['src', 'dest', 'seq', 'ack', 'off_res', 'flags', 'awnd', 'chksm', 'urg']
pseudo_header_format = '4s4sBBH'

# URL trimming to get host name for DEST_ADDR
trimUrl = url
if url.startswith('http://'):
    trimUrl = url[7:]
    url = trimUrl
elif url.startswith('https://'):
    trimUrl = url[8:]
    url = trimUrl
if '/' in trimUrl:
    i = trimUrl.find('/')
    trimUrl = trimUrl[0:i]
        
# These should be constant for the whole program, while sending packets
# TCP Side
SRC_PORT = 8080
DEST_PORT = 80
OFFSET = 5
AWND = socket.htons(1500) # MTU of ethernet
URG = 0

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
DEST_ADDR = socket.inet_aton(socket.gethostbyname(trimUrl))

# Global variables
seq = random.randint(0, 2**32)
ack = 0

# Keeps track of out-of-order packets
lastOrderedSeq = 0
packetBuffer = []

def tcpwrap(seq, ack, flags, data):
    """
    Takes in TCP header parameters and creates the correct TCP header and adds it to the data.
    Returns the new message with the TCP header added. Offset is automatically calculated.
    :param seq: the sequence number of the current packet. += 1 beforehand.
    :param ack: the acknowledgment number
    :param flags: any flags
    :param data: the data to be wrapped
    :return: the packet wrapped with the TCP header
    """
    
    # Create pseudo-header to calculate checksum
    temp_header = pack(tcp_temp_header_format, SRC_PORT, DEST_PORT, seq, ack, 0x50,
                      flags, AWND, 0, URG)
    total_len = len(temp_header) + len(data)
    pseudo_header = pack(pseudo_header_format, SRC_ADDR, DEST_ADDR, 0, PROTO, total_len);
    check = checksum(temp_header + pseudo_header + data.encode())
    
    tcp_header = pack(tcp_header_format, SRC_PORT, DEST_PORT, seq, ack, OFFSET << 4, flags,
                      AWND) + pack('H', check) + pack('!H', URG)
    tcp_packet = tcp_header + data.encode()
    return tcp_packet

def tcpunwrap(tcp_packet):
    """
    Takes a tcp packet and extracts out the header, returning the contained data. Validates the 
    :param tcp_packet: the packet to be unwrapped
    :return: a dictionary of the headers and the unwrapped data
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

    if tcp_headers['dest'] != SRC_PORT:
        raise ValueError("incorrect destination port")
    
    if tcp_verify_checksum(tcp_header_vals, options, tcp_data):
        return tcp_headers, tcp_data
    else:
        #TCP HEADER OR DATA CHECKSUM HAS FAILED. TODO
        print ('checksum has failed. replicate TCP ACK behavior')

def ipwrap(tcp_packet):
    """
    Takes in the IP header parameters and constructs a IP header, which is added to the given data and returned.
    :param tcp_packet: the full packet given out by tcpwrap, including payload
    :return: the full IP packet, including the TCP packet
    """
    check = 0 # kernel will fill correct checksum
    pktId = random.randint(0, 65534)
    total_len = len(tcp_packet) + 20
    return pack(ip_header_format, IHL_VERSION, TOS, total_len, pktId, FRAG_OFF, 
                TTL, PROTO, check, SRC_ADDR, DEST_ADDR) + tcp_packet

def ipunwrap(ip_packet):
    """
    Takes an ip packet and extracts the headers and the data
    :param ip_packet: the packet to be unwrapped
    :return: a dictionary of the headers and the unwrapped data
    """
    ip_header_vals = unpack(ip_header_format, ip_packet[0:20])
    ip_headers = dict(zip(ip_header_keys, ip_header_vals))
    
    version = ip_headers['ver_ihl'] >> 4
    if version != 4:
        raise ValueError("not IPv4")
    ihl = ip_headers['ver_ihl'] & 0x0F

    # check that this is the destination
    if ip_headers['dest'] != hostIP_hex:
        raise ValueError("invalid destination IP address")

    # check that is tcp packet
    print('protocol: ' + str(ip_headers['proto']))
    if ip_headers['proto'] != 0x06:
        raise ValueError("Not TCP packet")
    
    print('size of ip packet: ' + str(ip_headers['tot_len']))
    print('ip_id: ' + str(ip_headers['id']))
    # get the data from the ip packet
    ip_data = ip_packet[4*ihl:]
    
    if (ip_verify_checksum(ip_header_vals)):
        return ip_headers, ip_data
    else:
        #IP HEADER CHECKSUM HAS FAILED. TODO
        print ('checksum has failed. replicate TCP ACK behavior')
        raise ValueError("invalid IP checksum")

# Referenced from Suraj Bisht of Bitforestinfo
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i]
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise ValueError("Something Wrong here")


    # One's Complement
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def tcp_verify_checksum(headerVals, opt, data):
    chcksm = headerVals[7]
    headerAndData = pack(tcp_header_format, headerVals[0],headerVals[1],headerVals[2],headerVals[3],headerVals[4],
            headerVals[5], headerVals[6], 0, headerVals[8], opt, data)
    calculatedChecksum = checksum(headerAndData)
    return calculatedChecksum == chcksm
    
def ip_verify_checksum(headerVals):
    chcksm = headerVals[7]
    ipHeader = pack(ip_header_format, headerVals[0],headerVals[1],headerVals[2],headerVals[3],headerVals[4],
            headerVals[5], headerVals[6], 0, headerVals[8], headerVals[9])
    calculatedChecksum = checksum(ipHeader)
    return calculatedChecksum == chcksm
    
# VERY untested. To be completed later.
# TODO: finish function and test
def tcp_handshake():
    global seq, ack
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    sendPacket(seq, 0, tcp_flags, '')

    starttime = time.clock()
    while time.clock() < starttime + TIMEOUT:
        ip_packet = recSock.recv(65536)
        try:
            ip_headers, ip_data = ipunwrap(ip_packet)
        except ValueError:
            continue
        try:
            tcp_headers, tcp_data = tcpunwrap(ip_data)
            # check for a syn/ack message
            if tcp_headers['flags'] & 0x12 != 0x12:
                continue
            break
        except ValueError:
            continue

    rec_ack = tcp_headers['ack']
    if seq == rec_ack - 1:
        #TODO
        print("Got an ACK back. Time to send an ACK and finish handshake.")
        # finish handshake
        # increment sequence number
        seq += 1
        # get the ack number from the SYN/ACK
        rec_syn = tcp_headers['syn']
        ack = rec_syn + 1
        # set the flags to ack
        tcp_flags = 0x10
        # send the ack message
        sendPacket(seq, ack, tcp_flags, '')

    else:
        print("Handshake failed!")
        
def change_file_name(myUrl):
    fileName = ''
    lastSlashIndex = myUrl.rfind('/')
    if lastSlashIndex == -1:
        fileName = 'index.html'
    else:
        if lastSlashIndex == len(myUrl) - 1:
            fileName = 'index.html'
        else:
            fileName = myUrl[lastSlashIndex + 1:]
    return fileName

# Use this without messing with IP wrap and TCP wrap, ideally
def sendPacket(seq, ack, flags, data):
    tcpPacket = tcpwrap(seq, ack, flags, data)
    ipPacket = ipwrap(tcpPacket)
    sendSock.sendto(ipPacket, (trimUrl, DEST_PORT))
    
def packetInOrder(packet):
    global lastOrderedSeq
    tcpPacket = ipunwrap(packet)
    tcp_header_vals = unpack(tcp_header_format, tcpPacket[0:20])
    
    packetSeq = tcp_header_vals[2]
    if packetSeq == lastOrderedSeq + 1:
        lastOrderedSeq += 1
        return True
    else:
        return False

def bufferPacket(packet):
    packetBuffer.append(packet)
    if len(packetBuffer) > 10:
        packetBuffer.clear()
        print ("Packet probably dropped. Resend the appropriate request.")
        #TODO: Resend GET request
        
def putPacketsInOrder(packet):
    # Returns list of in-order packets while updating lastOrderedSeq 
    global lastOrderedSeq
    global packetBuffer
    
    tcpPkt = ipunwrap(packet)
    tcpHeader = unpack(tcp_header_format, tcpPkt[0:20])
    pktSeq = tcpHeader[2]
    lastSeq = pktSeq    
    
    orderedPackets = [packet]
    temp = packetBuffer
    
    i = 0
    while i < len(packetBuffer):
        p = packetBuffer[i]
        tcpPacket = ipunwrap(p)
        tcp_header_vals = unpack(tcp_header_format, tcpPacket[0:20])
        packetSeq = tcp_header_vals[2]
        
        if packetSeq == lastSeq + 1:
            orderedPackets.append(p)
            lastSeq += 1
            temp.remove(p)
        
        i += 1
    packetBuffer = temp
    lastOrderedSeq = lastSeq
    return orderedPackets
    
#############################################################################
def run():
    fileName = change_file_name(url)
        
    f = open(fileName, 'wb+')

    # TODO: perform TCP handshake, get seq/ack numbers for use in rest of program
    # TODO: ADD THAT TRY/CATCH SOCKET CONNECTION HERE!
    tcp_handshake()
    
    # TODO: send HTTP GET request (maybe can be done at the end of the handshake?)

    # TODO: get the HTTP response (by listening and responding with appropriate acks)
    # AFTERWARDS! call packetInOrder(packet)
    # if returns false, run bufferPacket(packet)
    # then upon the first True-returned packetInOrder, call putPacketsInOrder
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
