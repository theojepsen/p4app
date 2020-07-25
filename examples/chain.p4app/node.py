#!/usr/bin/env python
import sys
from scapy.all import *
from ChainRep_headers import *
from async_sniff import sniff
from threading import Thread, Event

IFACE = 'eth0'

if len(sys.argv) != 1:
    print "Usage: %s" % (sys.argv[0],)
    sys.exit(1)

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
            p[IP].dst = p[ChainRep].nodes[1]
        # TODO: this does not update the packet correctly
        p[ChainRep].nodes = p[ChainRep].nodes[1:]
        p.show()
        p.show2()
        sendp(p, iface=IFACE)
    else:
        raise Exception("Unknown OP: 0x%x" % p[ChainRep].op)



#sniffer = AsyncSniffer(iface=IFACE, prn=handle_pkt)
#sniffer.start()

stop_event = Event()

def sniffer():
    sniff(iface=IFACE, prn=handle_pkt, stop_event=stop_event)

sniff_thread = Thread(target=sniffer)
sniff_thread.start()

raw_input("Hit any key to exit.")
stop_event.set()

print "exiting..."

#sniffer.stop()
sniff_thread.join()
