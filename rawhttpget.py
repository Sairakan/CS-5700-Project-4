# -*- coding: utf-8 -*-
"""
Spyder Editor

Authors: Jason Teng, Jae Son
"""

from socket import AF_PACKET, SOCK_RAW, IPPROTO_RAW, IPPROTO_IP
import socket, argparse

parser = argparse.ArgumentParser(description='Client script for Project 4')
parser.add_argument('url', help='URL')

args = parser.parse_args()

url = args.url

sendSock = socket.socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)
recSock = socket.socket(AF_PACKET, SOCK_RAW, IPPROTO_IP)

# gets the host ip by creating a connection to Google and observing the socket parameters
hostIP = [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]

print hostIP
