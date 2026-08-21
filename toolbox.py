#!/usr/bin/env python
#
# Author: Tianshu Shen
# Coding: utf-8
# Usage: this is a helper variable and function collection
#        should not be run directly

'''
All following functions can be classified to 5 categories
1. Convert between int and bytes: byte16/32_to_int, int_to_byte16/32
2. Decode and encode of DNS names: name_decode, name_encode_compress
3. Build and resolve message: parse, build_record_compress, build_response, build_query
4. Interact with upsteam servers: ask_server, resolve, extract_next_servers
5. TTL cache: cache_get, cache_put, cache_lookup
'''

import socket
import random
import time
import threading

rcode_dict={
    0:'NOERROR',  # Success
    1:'FORMERR',  # Format error
    2:'SERVFAIL',  # Server failure
    3:'NXDOMAIN',  # Non-existent domain
    4:'NOTIMP',  # Not implemented
    5:'REFUSED'  # Query refused
}
qtype_dict={
    1:'A',
    2:'NS',
    5:'CNAME',
    6:'SOA',
    12:'PTR',
    15:'MX',
    16:'TXT',
    28:'AAAA',
    33:'SRV',
    35:'NAPTR',
    39:'DNAME',
    41:'OPT',
    43:'DS',
    46:'RRSIG',
    47:'NSEC',
    48:'DNSKEY',
    50:'NSEC3',
    51:'NSEC3PARAM',
    52:'TLSA',
    64:'SVCB',
    65:'HTTPS',
    255:'ANY'
}
qtype_reverse={t:i for i,t in qtype_dict.items()}

qclass_dict={
    1:'IN'  # query class is always 'IN' so QCLASS=1
}
qclass_reverse={c:i for i,c in qclass_dict.items()}

def byte16_to_int(data:bytes,p:int)->int:  # read a 16-bit unsigned integer in network byte order
    high_byte=data[p]
    low_byte=data[p+1]
    high_byte=high_byte<<8
    return high_byte | low_byte

def byte32_to_int(data:bytes,p:int)->int:  # read a 32-bit unsigned integer in network byte order
    left_1_byte=data[p]
    left_2_byte=data[p+1]
    right_2_byte=data[p+2]
    right_1_byte=data[p+3]

    left_1_byte=left_1_byte<<24
    left_2_byte=left_2_byte<<16
    right_2_byte=right_2_byte<<8
    return left_1_byte | left_2_byte | right_2_byte | right_1_byte

def int_to_byte16(n:int)->bytes:
    high_byte=n//256
    low_byte=n%256
    return bytes([high_byte,low_byte])

def int_to_byte32(n:int)->bytes:
    left_1_byte=n//(256*256*256)
    n=n%(256*256*256)
    left_2_byte=n//(256*256)
    n=n%(256*256)
    right_2_byte=n//256
    right_1_byte=n%256
    return bytes([left_1_byte,left_2_byte,right_2_byte,right_1_byte])
    
def name_decode(data:bytes,p:int)->tuple[str,int]:  # return(aname,next flag to read)
    jump_times=0
    jumped=lambda:jump_times!=0
    aname_list=[]
    flag=None

    while True:
        if jump_times>20:  # maximum times of jump otherwise loop
            raise ValueError
        if sum(len(x) for x in aname_list)+len(aname_list)>255:  # maximum length of name
            raise ValueError
        if p>=len(data):
            raise ValueError

        length=data[p]

        if length==0:  # 0x00
            if not jumped():
                flag=p+1
            break
        elif length>>6==0b00:  # the leading 2 digits are 00 thus this is len of label
            if p+1>len(data) or p+1+length>len(data):  # index of read>len(data)
                raise ValueError
            p+=1
            aname_list.append(data[p:p+length].decode('ascii'))
            p+=length
        elif length>>6==0b11:  # the leading 2 digits are 11 thus this is compressed pointer
            if not jumped():
                flag=p+2
            jump_times+=1
            jump_p=length & 0b111111  # drop the 2 flag bits, keep the low 6 as the high half
            jump_p=jump_p<<8  # offset is 14 bits: these 6 plus the next whole byte
            if p+1>=len(data):  # pointer takes 2 bytes thus 2nd bytes must exist
                raise ValueError
            jump_p=jump_p+data[p+1]
            p=jump_p
        else:
            raise ValueError

    aname_string='.'.join(aname_list)+'.'
    return aname_string,flag

# for unsupported RDATA we return its len but not decode
def unsupported_rdata(rdlength):
    return 'RDLENGTH='+str(rdlength)

# write name into message and use compressed pointer if possible
def name_encode_compress(name:str,msg:bytearray,name_cache:dict)->None:
    if name=='.' or name =='':
        msg.append(0)
        return

    labels=name.strip('.').split('.')
    i=0
    while i<len(labels):
        suffix='.'.join(labels[i:])+'.'
        if suffix in name_cache:
            offset=name_cache[suffix]
            high_byte=offset>>8  # move right 8 to get leading digit
            low_byte=offset & 0xFF
            pointer_high=0xC0 | high_byte  # set the top 2 bits to 11 to mark it as a pointer
            msg.append(pointer_high)
            msg.append(low_byte)
            return  # a pointer always ends the name, nothing more to write
        
        name_cache[suffix]=len(msg)   # record the current offset
        label=labels[i]
        label_bytes=label.encode('ascii')
        msg.append(len(label_bytes))
        msg.extend(label_bytes)
        i+=1
    msg.append(0)  # reached only if no suffix was reusable; a name ends with a zero length byte

# build flags for response by client query flags
def flags_rebuild(flags,rcode=0,aa=0):
    opcode=(flags//2048)%16
    rd=(flags//256)%2
    resp_flags=(
        1*32768+
        opcode*2048+
        aa*1024+
        0*512+
        rd*256+
        1*128+
        0*16+
        rcode)
    return resp_flags

# append one resource record to the shared msg, not return its own bytes,
# because pointer offsets are counted from the start of the whole message
def build_record_compress(msg:bytearray,name_cache:dict,owner:str,rtype:str,rclass:str,ttl:int,rdata:str)->None:
    name_encode_compress(owner,msg,name_cache)
    msg.extend(int_to_byte16(qtype_reverse[rtype]))
    msg.extend(int_to_byte16(qclass_reverse[rclass]))
    msg.extend(int_to_byte32(ttl))
    rdlength_pos=len(msg)  # mark the position, come back to fill after writing rdata
    msg.extend(b'\x00\x00')

    if rtype in ('NS','CNAME','PTR'):
        name_encode_compress(rdata,msg,name_cache)
    elif rtype=='A':
        msg.extend(bytes(int(x) for x in rdata.split('.')))
    elif rtype=='MX':
        pref,mxname=rdata.split(' ',1)
        msg.extend(int_to_byte16(int(pref)))
        name_encode_compress(mxname,msg,name_cache)
    else:
        raise ValueError

    # backfill the actual RDLENGTH
    rdlength=len(msg)-rdlength_pos-2
    msg[rdlength_pos:rdlength_pos+2]=int_to_byte16(rdlength)

# build client response
def build_response(
    msg_id,client_flags,qname,qtype,qclass,
    answer_records=None,authority_records=None,
    additional_records=None,rcode=0,aa=0)->bytes:
    answer_records=answer_records or []
    authority_records=authority_records or []
    additional_records=additional_records or []

    msg=bytearray()
    name_cache={}

    # flags are built here, where rcode is already known
    msg.extend(int_to_byte16(msg_id))
    msg.extend(int_to_byte16(flags_rebuild(client_flags,rcode,aa)))
    msg.extend(int_to_byte16(1))  # QDCOUNT
    msg.extend(int_to_byte16(len(answer_records)))  # counts come from list length, never hand written
    msg.extend(int_to_byte16(len(authority_records)))
    msg.extend(int_to_byte16(len(additional_records)))

    # question
    name_encode_compress(qname,msg,name_cache)
    msg.extend(int_to_byte16(qtype))
    msg.extend(int_to_byte16(qclass))

    for rec in answer_records:
        build_record_compress(msg,name_cache,*rec)
    for rec in authority_records:
        build_record_compress(msg,name_cache,*rec)
    for rec in additional_records:
        build_record_compress(msg,name_cache,*rec)

    return bytes(msg)

# decode a binary DNS message into a dictionary
# shared by parser and the resolver.
def parse(data:bytes)->dict:
    # Header
    transaction_id=byte16_to_int(data,0)

    flags=byte16_to_int(data,2)
    flags_bin=bin(flags)[2:].zfill(16)

    qr=(flags_bin[0]=='1')

    opcode=flags_bin[1:5]
    opcode_int=int(opcode,2)

    aa=(flags_bin[5]=='1')
    tc=(flags_bin[6]=='1')
    rd=(flags_bin[7]=='1')
    ra=(flags_bin[8]=='1')

    rcode=flags_bin[12:]
    rcode_str=rcode_dict.get(int(rcode,2),str(int(rcode,2)))  # unknown rcode fall back to int.

    qdcount=byte16_to_int(data,4)  # 4,5
    ancount=byte16_to_int(data,6)  # 6,7
    nscount=byte16_to_int(data,8)  # 8,9
    arcount=byte16_to_int(data,10)  # 10,11

    # Question
    p=12
    qindex=0
    question_list=[]
    while qindex<=qdcount-1:
        qname=''
        qname,p=name_decode(data,p)
        qtype=byte16_to_int(data,p)
        qclass=byte16_to_int(data,p+2)
        question_list.append((qname,qtype,qclass))
        qindex+=1
        p+=4

    # Answers  # variable length
    answer_list,authority_list,additional_list=[],[],[]

    aindex=0

    while aindex<=ancount+nscount+arcount-1:

        if aindex in range(ancount):
            belonging='ANSWERS'
        elif aindex in range(ancount,ancount+nscount):
            belonging='AUTHORITY'
        elif aindex in range(ancount+nscount,ancount+nscount+arcount):
            belonging='ADDITIONAL'

        aname_string,p=name_decode(data,p)

        atype=byte16_to_int(data,p)
        atype_str=qtype_dict.get(atype,str(atype))

        aclass=byte16_to_int(data,p+2)
        aclass_str=qclass_dict.get(aclass,str(aclass))

        ttl=byte32_to_int(data,p+4)
        rdlength=byte16_to_int(data,p+8)
        
        rdata=''
        p+=10  # rdata starts from here

        if atype==1:  # if is A(ipv4)
            if rdlength!=4:
                rdata=unsupported_rdata(rdlength)
            else:
                for b in data[p:p+rdlength]:
                    rdata+=f"{b}."
                rdata=rdata[:-1]
        elif atype in (2,5,12):  # NS/CNAME/PTR
            try:
                rdata,flag=name_decode(data,p)
                if flag!=(p+rdlength):
                    rdata=unsupported_rdata(rdlength)
            except ValueError:
                rdata=unsupported_rdata(rdlength)
        elif atype==15:  # MX mail
            preference=byte16_to_int(data,p)  # 16-bit delivery priority, smaller is preferred
            try:
                mxname,flag=name_decode(data,p+2)
                if flag!=(p+rdlength):
                    rdata=unsupported_rdata(rdlength)
                else:  # all
                    rdata=str(preference)+' '+mxname
            except ValueError:
                rdata=unsupported_rdata(rdlength)
        else:
            rdata=unsupported_rdata(rdlength)
        p+=rdlength

        # parameter format consistent with build_record_compress
        record=(aname_string,atype_str,aclass_str,ttl,rdata)
        if belonging=='ANSWERS':
            answer_list.append(record)
        elif belonging=='AUTHORITY':
            authority_list.append(record)
        elif belonging=='ADDITIONAL':
            additional_list.append(record)

        aindex+=1

    return {
        'id':transaction_id,
        'qr':qr,
        'opcode':opcode_int,
        'aa':aa,
        'tc':tc,
        'rd':rd,
        'ra':ra,
        'rcode':int(rcode,2),
        'rcode_str':rcode_str,
        'counts':(qdcount,ancount,nscount,arcount),
        'questions':question_list,
        'answers':answer_list,
        'authority':authority_list,
        'additional':additional_list}

# build the query to send to the upstream server
def build_query(qname,qtype,qclass=1):
    query_id=random.randint(0,65535)  # our own id, never reuse the client's: it is publicly visible
    msg=bytearray()
    name_cache={}
    msg.extend(int_to_byte16(query_id))
    msg.extend(int_to_byte16(0))  # flags all zero, the point is RD=0: ask for a referral not recursion
    msg.extend(int_to_byte16(1))  # QDCOUNT=1
    msg.extend(int_to_byte16(0))  # ANCOUNT
    msg.extend(int_to_byte16(0))  # NSCOUNT
    msg.extend(int_to_byte16(0))  # ARCOUNT
    name_encode_compress(qname,msg,name_cache)
    msg.extend(int_to_byte16(qtype))
    msg.extend(int_to_byte16(qclass))
    return query_id,bytes(msg)  # id is for ask_server check

# send one query to ip:53, return the checked reply or None if this server failed
# the socket is not bound, so the OS gives a random source port: harder to forge a reply
def ask_server(ip,qname,qtype,qclass,timeout):
    query_id,query=build_query(qname,qtype,qclass)
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    try:
        s.sendto(query,(ip,53))
        deadline=time.time()+timeout
        while True:
            remaining=deadline-time.time()
            if remaining<=0:
                return None  # timeout, count as fail
            s.settimeout(remaining)
            data,src=s.recvfrom(4096)

            # any mismatch means noise or a forgery, so drop it and keep waiting
            if src[0]!=ip or src[1]!=53:
                continue
            try:
                msg=parse(data)
            except (ValueError,IndexError):
                return None  # malformed, count as fail
            if msg['id']!=query_id:
                continue
            if not msg['qr']:
                continue
            if msg['opcode'] != 0:
                continue
            if msg['counts'][0] != 1:
                continue
            q=msg['questions'][0]
            if q[0].lower()!=qname.lower():
                continue
            if q[1]!=qtype or q[2]!=qclass:
                continue

            return msg  # pass all check
    except socket.timeout:
        return None
    finally:
        s.close()
    
# walk down the DNS tree from the roots until we get an answer
# outer while = one level, inner for = the candidate servers on that level
def resolve(qname,qtype,qclass,root_ips,timeout,budget,cname_chain=None):
    # returns ('OK',answers,authority,additional,aa) / ('NXDOMAIN'|'NODATA',chain) / ('SERVFAIL',None)
    if cname_chain is None:
        cname_chain=[]
    qtype_str=qtype_dict.get(qtype,str(qtype))
    qclass_str=qclass_dict.get(qclass,str(qclass))

    servers=list(root_ips)  # current candidates, replaced every time we follow a referral

    while True:
        if budget['referrals']>=10:
            return ('SERVFAIL',None)

        for ip in servers:
            if budget['attempts']>=50 or time.time()>=budget['deadline']:
                return ('SERVFAIL',None)
            budget['attempts']+=1

            msg=ask_server(ip,qname,qtype,qclass,timeout)
            if msg is None or msg['tc']:
                continue  # go next

            # walk the CNAME chain inside this one reply as far as it goes
            cur=qname
            local_chain=[]
            while True:
                rrset=[r for r in msg['answers']
                       if r[0].lower()==cur.lower()
                       and r[1]==qtype_str and r[2]==qclass_str]
                if rrset:
                    aa = msg['aa'] and not cname_chain and not local_chain
                    return ('OK',cname_chain+local_chain+rrset,
                            msg['authority'],msg['additional'],aa)
                cn=[r for r in msg['answers']
                    if r[0].lower()==cur.lower() and r[1]=='CNAME']
                if not cn:
                    break
                if len(cname_chain)+len(local_chain)>=10:
                    return ('SERVFAIL',None)   # chain too long
                local_chain.append(cn[0])
                cur=cn[0][4]

            # chain ran out inside this reply, so restart from the roots with the new name
            if local_chain:
                return resolve(
                    cur,qtype,qclass,root_ips,timeout,budget,
                    cname_chain+local_chain)
            # 3:NXDOMAIN
            if msg['rcode']==3:
                return ('NXDOMAIN',cname_chain)
            # 4:NODATA
            if msg['aa'] and msg['rcode']==0:
                return ('NODATA',cname_chain)
            # 5:referral
            next_ips,no_glue=extract_next_servers(msg)
            if not next_ips and no_glue:
                # no glue:nested query to resolve the A records of the NS name
                for nsname in no_glue:
                    sub=resolve(nsname,1,1,root_ips,timeout,budget)
                    if sub[0]=='OK':
                        next_ips=[r[4] for r in sub[1] if r[1]=='A']
                        if next_ips:
                            break
            if next_ips:
                servers=next_ips
                budget['referrals']+=1
                break  # back to while loop top and continue with the new candidate
            # all others considered fail
            continue
        else:
            return ('SERVFAIL',None)  # loop finish without break -> all candidates fail

# extract next round candidates from referral response
def extract_next_servers(msg):
    ns_names=[r[4] for r in msg['authority'] if r[1]=='NS']  # keep the order they appear in the packet
    ips=[]
    no_glue=[]
    for ns in ns_names:
        found=[r[4] for r in msg['additional']
               if r[1]=='A' and r[0].lower()==ns.lower()]  # ipv4 only not ipv6
        if found:
            ips.extend(found)
        else:
            no_glue.append(ns)
    return ips,no_glue  # ip list, list of NS names without glue records

# key is what identifies one RRset, value is (records, the clock time it expires)
# an absolute time is stored, not a TTL, because a TTL goes stale while it sits here
cache={}
cache_lock=threading.Lock()

# fetch one RRset with its TTL counted down to what is left; None if missing or expired
def cache_get(name,rtype,rclass):
    key=(name.lower(),rtype,rclass)
    now=time.time()
    with cache_lock:
        entry=cache.get(key)
        if entry is None:
            return None
        records,expiry=entry
        remaining=int(expiry-now)
        if remaining<=0:
            del cache[key]  # expired
            return None
    return [(r[0],r[1],r[2],remaining,r[4]) for r in records]  # rewrite ttl

# store record(name,type,class) to the cache
def cache_put(records):
    now=time.time()
    groups={}
    for r in records:
        if r[3]<=0:  # not store if ttl=0
            continue
        groups.setdefault((r[0].lower(),r[1],r[2]),[]).append(r)
    with cache_lock:
        for key,recs in groups.items():
            ttl=min(x[3] for x in recs)  # the set expires together, so take the shortest to be safe
            cache[key]=(recs,now+ttl)

# look up the asked type first, otherwise follow the CNAME chain step by step
# if any step is missing or expired the whole thing counts as a miss and we go ask the servers
def cache_lookup(qname,qtype_str,qclass_str):
    chain=[]
    cur=qname
    for i in range(10):  # maximum cache lookup chain len 10
        rrset=cache_get(cur,qtype_str,qclass_str)
        if rrset:
            return chain+rrset
        cn=cache_get(cur,'CNAME',qclass_str)
        if not cn:
            return None  # chain is broken here, so answer nothing and let resolve() do the real lookup
        chain.extend(cn)
        cur=cn[0][4]
    return None