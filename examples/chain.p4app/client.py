#!/usr/bin/env python
from scapy.all import *
from ChainRep_headers import *
from threading import Thread, Event
from async_sniff import sniff

IFACE = 'eth0'
my_mac = get_if_hwaddr(IFACE)
my_ip = get_if_addr(IFACE)
VERBOSE_SENDP = False

def make_pkt(nodes, op=CHAINREP_OP_READ, key=0, val=0, seq=0):
    assert len(nodes) > 0
    dst_ip = nodes[0]
    return Ether(dst='00:11:22:33:44:55', src=my_mac) / \
            IP(dst=dst_ip, src=my_ip) / \
            ChainRep(nodes=nodes[1:], op=op, seq=seq, key=key, value=val)


stop_event = Event()
packet_received = Event()
recv = []

def handle_pkt(p):
    if p.haslayer(Ether) and p[Ether].src == my_mac: return
    if p.haslayer(IP) and p[IP].src == my_ip: return
    if not p.haslayer(ChainRep): return
    #p.show2()
    packet_received.set()
    recv.append(p)

def sniffer(): sniff(iface=IFACE, prn=handle_pkt, stop_event=stop_event)
sniff_thread = Thread(target=sniffer)
sniff_thread.start()

nodes = ['10.0.0.1', '10.0.0.2', '10.0.0.3']

p = make_pkt(nodes, op=CHAINREP_OP_WRITE, key=1, val=0xaa)
sendp(p, iface=IFACE, verbose=VERBOSE_SENDP)
packet_received.wait()
packet_received.clear()
assert recv[0].haslayer(ChainRep)
assert recv[0][IP].src == nodes[-1]
assert recv[0][ChainRep].node_cnt == 0
assert recv[0][ChainRep].key == 1
assert recv[0][ChainRep].value == 0xaa

p = make_pkt(list(reversed(nodes)), op=CHAINREP_OP_READ, key=1)
sendp(p, iface=IFACE, verbose=VERBOSE_SENDP)
packet_received.wait()
packet_received.clear()
#recv[1].show()
assert recv[1].haslayer(ChainRep)
assert recv[1][IP].src == nodes[-1]
assert recv[1][ChainRep].node_cnt == 2
assert recv[1][ChainRep].key == 1
assert recv[1][ChainRep].value == 0xaa

stop_event.set()
sniff_thread.join()
