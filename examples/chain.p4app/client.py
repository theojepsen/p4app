#!/usr/bin/env python
import sys
from scapy.all import *
from ChainRep_headers import *

IFACE = 'eth0'
src_mac = get_if_hwaddr(IFACE)

#if len(sys.argv) != 2:
#    print "Usage: %s DST_IP" % (sys.argv[0],)
#    sys.exit(1)
#
#dst_ip = sys.argv[1]

def make_pkt(nodes, op=CHAINREP_OP_READ, key=0, val=0, seq=0):
    assert len(nodes) > 0
    dst_ip = nodes[0]
    return Ether(dst='00:11:22:33:44:55', src='00:11:22:33:44:56') / \
            IP(dst=dst_ip) / \
            ChainRep(nodes=nodes, op=op, seq=seq, key=key, value=val)

kv_store = {1: 0x11, 2: 0x22}

def handle_pkt(p):
    #p.show2()
    if not p.haslayer(ChainRep): return
    if p[ChainRep].node_cnt == 0:
        print "No nodes in chain"
        return
    if p[ChainRep].op == CHAINREP_OP_READ:
        p[IP].dst = p[IP].src
        p[IP].src = p[ChainRep].nodes[0]
        p[ChainRep].value = kv_store[p[ChainRep].key]
        p[ChainRep].nodes = p[ChainRep].nodes[1:]
        print "Got READ for 0x%x (0x%x) from" % (p[ChainRep].key, p[ChainRep].value), p[IP].src
        sendp(p, iface=IFACE)
    elif p[ChainRep].op == CHAINREP_OP_WRITE:
        kv_store[p[ChainRep].key] = p[ChainRep].value
        print "Got WRITE for 0x%x (0x%x) from" % (p[ChainRep].key, p[ChainRep].value), p[IP].src
        if p[ChainRep].node_cnt == 1: # we are at the tail
            p[IP].src = p[ChainRep].nodes[0]
            p[IP].dst = p[IP].src
        else:
            p[IP].dst = p[ChainRep].nodes[0]
        p[ChainRep].nodes = p[ChainRep].nodes[1:]
        sendp(p, iface=IFACE)
    else:
        raise Exception("Unknown OP: 0x%x" % p[ChainRep].op)


p = make_pkt(['10.0.0.1', '10.0.0.2'], op=CHAINREP_OP_WRITE, key=1, val=0xaa)
sendp(p, iface=IFACE)

raw_input("Hit any key to exit.")
