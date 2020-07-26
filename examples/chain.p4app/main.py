from p4app import P4Mininet
from mininet.topo import Topo
import subprocess
import sys
import time

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')

        for i in xrange(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)

NUM_NODES = 3
NUM_CLIENTS = 1
NUM_HOSTS = NUM_NODES + NUM_CLIENTS

topo = SingleSwitchTopo(NUM_HOSTS)
net = P4Mininet(program='basic.p4', topo=topo)
net.start()

sw = net.get('s1')

for i in range(1, NUM_HOSTS+1):
    h = net.get('h%d' % i)

    sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
                        action_name='MyIngress.set_egr',
                        action_params={'port': i})

node_hosts = [net.get('h%d'%i) for i in range(1, NUM_NODES+1)]
cl_host = net.get('h%d'%(NUM_NODES+1))

node_procs = [h.popen('./node.py', stdout=sys.stdout, stderr=sys.stdout, stdin=subprocess.PIPE) for h in node_hosts]

time.sleep(0.2) # hack: wait for nodes to be ready
cl_proc = cl_host.popen('./client.py', stdout=sys.stdout, stderr=sys.stdout, stdin=subprocess.PIPE)
cl_proc.communicate(input='\n')

for p in node_procs:
    p.communicate(input='\n')
