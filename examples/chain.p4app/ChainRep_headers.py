from scapy.all import *

CHAINREP_PROTO = 0x98

CHAINREP_OP_READ  = 1
CHAINREP_OP_WRITE = 2

class ChainRep(Packet):
    fields_desc=[
       FieldLenField("node_cnt", None, count_of="nodes", fmt="B"),
       FieldListField("nodes", ["1.2.3.4"], IPField("", "0.0.0.0"),
                       count_from = lambda pkt: pkt.node_cnt),
       ByteEnumField("op", 1, {1:"READ", 2:"WRITE"}),
       ByteField("seq", 0),
       XIntField("key", 0),
       XLongField("value", 0)
       ]

bind_layers(IP, ChainRep, proto=CHAINREP_PROTO)

