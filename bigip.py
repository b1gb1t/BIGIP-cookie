#!/usr/bin/python3

import struct
import sys
import re
import argparse

def decode(cookie):
    print('[*] Cookie to decode: {}\n'.format(cookie))

    cookie_name, cookie_value = cookie.split('=')
    pool = re.search('^BIGipServer([.\w\.]*)', cookie_name)
    
    host, port, end = cookie_value.split('.')
    a, b, c, d = [i for i in struct.pack("<I", int(host))]
    e = [e for e in struct.pack("<H", int(port))]
    port = "0x%02X%02X" % (e[0],e[1])

    if pool:
        print('[+] Pool name: {}'.format(pool.group(1)))
    else:
        print('[-]It was not possible to identify the pool')
    
    print('[+] Decoded IP and Port: {}.{}.{}.{}:{}\n'.format(a,b,c,d, int(port,16)))

def encode(endpoint):
    ip, port = endpoint.split(':')
    ip = ip.split('.')
    ip.reverse()
    enc_ip = []

    for i in ip:
        enc_ip.append(hex(int(i))[2:])

    enc_ip = ''.join(map(lambda x: x.zfill(2), enc_ip))
    
    port = hex(int(port))[2:]
    enc_port = []
    
    for i in range(0, len(port), 2):
        enc_port.append(str(port[i:i+2]))

    enc_port.reverse()
    enc_port = ''.join(enc_port)
    print("[+] Encoded BigIP Cookie: {}.{}.0000\n".format(int(enc_ip,16), int(enc_port,16)))


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--decode", action="store_true", 
                        help="Decode BigIP cookie")
    parser.add_argument("-c", "--cookie", 
                        help="Cookie name and value (p.e. cookie=value")
    parser.add_argument("-ip",
                        help="IP:port to encode")
    args = parser.parse_args()
    
    if args.decode:
        if args.cookie: decode(args.cookie)
    else:
        if args.ip: encode(args.ip)
        else: parser.print_help()
