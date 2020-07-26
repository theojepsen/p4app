#!/usr/bin/env python
from scapy.all import *
from ChainRep_headers import *
from async_sniff import sniff
from threading import Thread, Event

IFACE = 'eth0'
my_mac = get_if_hwaddr(IFACE)
my_ip = get_if_addr(IFACE)

my_state = {'seq': 0, 'vals': {1: 0x11, 2: 0x22}}

def handle_pkt(p):
    if p.haslayer(Ether) and p[Ether].src == my_mac: return
    if not p.haslayer(ChainRep): return

    if p[ChainRep].op == CHAINREP_OP_READ:
        print "[%s] READ(0x%x)=0x%x   chain: %s   src: %s)" % (my_ip, p[ChainRep].key, p[ChainRep].value, p[ChainRep].nodes, p[IP].src)
        p[IP].dst = p[IP].src
        p[IP].src = my_ip
        p[ChainRep].value = my_state['vals'][p[ChainRep].key]
    elif p[ChainRep].op == CHAINREP_OP_WRITE:
        print "[%s] WRITE(0x%x, 0x%x)   seq: %d   chain: %s   src: %s" % (my_ip, p[ChainRep].key, p[ChainRep].value, p[ChainRep].seq, p[ChainRep].nodes, p[IP].src)
        if p[ChainRep].seq < my_state['seq']: return # drop packet
        my_state['seq'] = p[ChainRep].seq
        my_state['vals'][p[ChainRep].key] = p[ChainRep].value
        if p[ChainRep].node_cnt == 0: # we are at the tail
            p[IP].dst = p[IP].src
            p[IP].src = my_ip
        else:
            p[IP].dst = p[ChainRep].nodes[0]
            p[ChainRep].nodes = p[ChainRep].nodes[1:]
            p[ChainRep].node_cnt -= 1
    else:
        raise Exception("Unknown OP: 0x%x" % p[ChainRep].op)

    p[Ether].src = my_mac
    #p.show2()
    sendp(p, iface=IFACE, verbose=False)

stop_event = Event()

def sniffer(): sniff(iface=IFACE, prn=handle_pkt, stop_event=stop_event)
sniff_thread = Thread(target=sniffer)
sniff_thread.start()

raw_input()

stop_event.set()
sniff_thread.join()
