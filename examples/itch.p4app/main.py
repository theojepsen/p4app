from p4app import P4Mininet
from mininet.topo import Topo
from camus import CamusApp
import subprocess
import sys
import time

n = 3

itch_app = CamusApp('spec.p4', ingress_name='MyIngress')
itch_app.generateQueryPipeline('itch_camus.p4')

rules = ['add_order.shares = 1: fwd(1);',
         'add_order.price = 2: fwd(2);',
         'add_order.shares = 3 and add_order.price = 4: fwd(3);',
         'add_order.shares > 100 and add_order.stock = "BFN": fwd(2);']

runtime_config = itch_app.compileRules(rules=rules, ingress_name='MyIngress')

print runtime_config.mcastGroups()

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')

        for i in xrange(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)

topo = SingleSwitchTopo(n)
net = P4Mininet(program='itch.p4', topo=topo)
net.start()


sw = net.get('s1')
h1, h2 = net.get('h1'), net.get('h2')

for i in range(1, n+1):

    # Forward to the host connected to this switch
    sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'port': i})

    sw.insertTableEntry(table_name='MyEgress.rewrite_mac',
                        match_fields={'standard_metadata.egress_port': i},
                        action_name='MyEgress.set_mac',
                        action_params={'dstAddr': '00:00:00:00:00:%02x' % i})


for entry in runtime_config.entries():
    #print entry['table_name'], entry['match_fields'], entry['action_params'] if 'action_params' in entry else ''
    sw.insertTableEntry(**entry)


net.pingAll()

subscriber = h1.popen('./subscriber.py 1234', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.2)

print h2.cmd('./publisher.py 10.255.255.255 1234')
time.sleep(0.2)

subscriber.terminate()
