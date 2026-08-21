#!/usr/bin/env python
#
# Author: Tianshu Shen
# Coding: utf-8
# Usage: python3 resolver.py root_hints_file timeout listen_port

import sys
import re
import socket
import random
import time
import threading

from toolbox import *

'''
read root hints file
ns_mapping: {owner: (NS target, ttl, type, class)}
a_mapping: {owner: (IPv4, ttl, type, class)}
'''

root_hints_file,timeout,listen_port=sys.argv[1:]
ns_mapping,a_mapping={},{}
file=open(root_hints_file)
a_pattern=r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'
ns_pattern=r'^[a-zA-Z0-9\-\.]*\.$'
default_ttl=0
for line in file:
    ttl,dns_type,dns_class,target,owner=None,None,None,None,None
    line=line.split(';')[0].strip()
    if not line:
        continue
    line=line.split()
    if '$TTL' in line:
        default_ttl=int(line[1])
        continue
        
    for part in line[1:-1]:
        if part.isdigit() and ttl is None:
            ttl=int(part)
        elif part.upper() in qclass_reverse and dns_class is None:
            dns_class=part.upper()
        elif part.upper() in qtype_reverse and dns_type is None:
            dns_type=part.upper()
    ttl=default_ttl if ttl is None else ttl
    # a master file may leave the class column out (RFC 1035 5.1); IN is the only
    # class this resolver serves, so an absent class is IN rather than unknown
    dns_class='IN' if dns_class is None else dns_class

    if not dns_type:
        continue

    # names are compared case-insensitively (RFC 4343) but the published root
    # hints spell the servers in upper case, so fold both ends of the NS-to-glue
    # join down here; leaving it to the lookup site is what broke on named.root
    if re.match(ns_pattern,line[0]):
        owner=line[0].lower()

    if dns_type=='NS' and re.match(ns_pattern,line[-1]):
        target=line[-1].lower()
        if owner in ns_mapping:
            ns_mapping[owner].append((target,ttl,dns_type,dns_class))
        else:
            ns_mapping[owner]=[(target,ttl,dns_type,dns_class)]
    elif dns_type=='A' and re.match(a_pattern,line[-1]):
        target=line[-1]
        if owner in a_mapping:
            a_mapping[owner].append((target,ttl,dns_type,dns_class))
        else:
            a_mapping[owner]=[(target,ttl,dns_type,dns_class)]

# pair each root NS name with its glue A record to get the 13 root server IPs
# NS gives a name and we cannot send a packet to a name, which is why the file lists both
root_ips=[]
for nsname,ttl,rtype,rclass in ns_mapping.get('.',[]):
    for ip,ttl2,t2,c2 in a_mapping.get(nsname.lower(),[]):
        root_ips.append(ip)

s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('127.0.0.1',int(listen_port)))

def handle_query(data,addr):
    try:
        msg_id=byte16_to_int(data,0)
        client_flags=byte16_to_int(data,2)
        qname,p=name_decode(data,12)
        qtype=byte16_to_int(data,p)
        qclass=byte16_to_int(data,p+2)
    except Exception:
        return  # question cannot be read -> discard
    try:
        answer_records=[]
        additional_records=[]
        rcode=0
        aa_bit=0

        if qname=='.' and qtype==2:  # CASE 1: root NS, answered from the file, no packet sent
            for ns_target,ns_ttl,ns_type,ns_class in ns_mapping.get('.',[]):
                answer_records.append(('.',ns_type,ns_class,ns_ttl,ns_target))
                for a_target,a_ttl,a_type,a_class in a_mapping.get(ns_target.lower(),[]):
                    additional_records.append((ns_target,a_type,a_class,a_ttl,a_target))
        elif qtype==1 and any(k.lower()==qname.lower() for k in a_mapping):  # CASE 2: root server A
            for key in a_mapping:
                if key.lower()==qname.lower():
                    for target,ttl,dns_type,dns_class in a_mapping[key]:
                        answer_records.append((key,dns_type,dns_class,ttl,target))
        elif qtype not in (1,2,5,12,15):  # all are unsupported query types
            rcode=2
        else:  # CASE 3: check the cache first; iterate cache not hit
            qtype_str=qtype_dict.get(qtype,str(qtype))
            qclass_str=qclass_dict.get(qclass,str(qclass))
            hit=cache_lookup(qname,qtype_str,qclass_str)
            if hit is not None:
                answer_records=hit  # answered from memory, no query goes out to any name server
            else:
                # a dict so the nested CNAME and no-glue lookups share the same limits
                budget={'attempts':0,'referrals':0,'deadline':time.time()+min(30,50*int(timeout))}
                status,*rest=resolve(qname,qtype,qclass,root_ips,int(timeout),budget)
                if status=='OK':
                    answer_records=rest[0]
                    aa_bit=rest[3]
                    cache_put(answer_records)
                elif status=='NODATA':
                    answer_records=rest[0]  # the CNAME chain, possibly empty
                elif status=='NXDOMAIN':
                    answer_records=rest[0]
                    rcode=3
                else:  # SERVFAIL
                    rcode=2

        response=build_response(
            msg_id,client_flags,qname,qtype,qclass,
            answer_records,[],additional_records,rcode,aa_bit)
    except Exception:
        # any unexpected error still must return SERVFAIL
        # one response for every valid query
        response=build_response(msg_id,client_flags,qname,qtype,qclass,rcode=2)
    s.sendto(response,addr)

while True:
    data,addr=s.recvfrom(512)  # set the message size limit to 512 bytes
    threading.Thread(target=handle_query,args=(data,addr),daemon=True).start()