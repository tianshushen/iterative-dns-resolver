#!/usr/bin/env python
#
# Author: Tianshu Shen
# Coding: utf-8
# Usage: python3 parser.py message_file

'''
read a binary DNS message file -> call parse to decode -> format and print the output
'''

import sys
import os

from toolbox import *

def main():
    message_file=sys.argv[1]
    if not os.path.isfile(message_file):
        print(sys.argv[0]+' error: '+sys.argv[1]+' not exist')
        raise FileNotFoundError

    with open(message_file,'rb') as f:
        data=f.read()

    msg=parse(data)
    qdcount,ancount,nscount,arcount=msg['counts']

    print(f"ID: {msg['id']}")
    print('--- FLAGS ---')
    print(f"QR: {msg['qr']}")
    print(f"Opcode: {msg['opcode']}")
    print(f"AA: {msg['aa']}")
    print(f"TC: {msg['tc']}")
    print(f"RD: {msg['rd']}")
    print(f"RA: {msg['ra']}")
    print(f"RCODE: {msg['rcode_str']}")
    print('--- COUNTS ---')
    print(f"Questions: {qdcount}")
    print(f"Answers: {ancount}")
    print(f"Authority: {nscount}")
    print(f"Additional: {arcount}")

    print('--- QUESTIONS ---')
    for qname,qtype,qclass in msg['questions']:
        print(f"{qname} {qclass_dict.get(qclass,str(qclass))} {qtype_dict.get(qtype,str(qtype))}")

    for title,key in (('--- ANSWERS ---','answers'),
                      ('--- AUTHORITY ---','authority'),
                      ('--- ADDITIONAL ---','additional')):
        print(title)
        for owner,rtype,rclass,ttl,rdata in msg[key]:
            print(f"{owner} {ttl} {rclass} {rtype} {rdata}")

if __name__=='__main__':
    try:
        main()
    except (ValueError,IndexError) as e:
        print('malformed DNS message: '+(str(e) or 'invalid encoding'))