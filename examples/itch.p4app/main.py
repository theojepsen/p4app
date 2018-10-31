from p4app import P4Mininet
from camus import CamusApp
from camus_topo import SingleSwitchTopo
import subprocess
import sys
import time

n = 3

itch_app = CamusApp('spec.p4', ingress_name='MyIngress')
itch_app.generateQueryPipeline('itch_camus.p4')

topo = SingleSwitchTopo(n)
topo.subscribe('h1', 'add_order.shares = 1')
topo.subscribe('h2', 'add_order.price = 2')
topo.subscribe('h3', 'add_order.shares = 3 and add_order.price = 4')
topo.subscribe('h2', 'add_order.shares > 100 and add_order.stock = "BFN"')
rules = topo.rules_for_sw['s1']
runtime_config = itch_app.compileRules(rules=rules, ingress_name='MyIngress')

net = P4Mininet(program='itch.p4', topo=topo)
net.start()

sw = net.get('s1')
h1, h2, h3 = net.get('h1'), net.get('h2'), net.get('h3')

for h in range(1, n+1):
    port = topo.switchPortForHost('h%d'%h)

    sw.insertTableEntry(table_name='MyIngress.ipv4_lpm',
                        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % h, 32]},
                        action_name='MyIngress.ipv4_forward',
                        action_params={'port': port})

    sw.insertTableEntry(table_name='MyEgress.rewrite_mac',
                        match_fields={'standard_metadata.egress_port': port},
                        action_name='MyEgress.set_mac',
                        action_params={'dstAddr': '00:00:00:00:00:%02x' % h})


for entry in runtime_config.entries():
    #print entry['table_name'], entry['match_fields'], entry['action_params'] if 'action_params' in entry else ''
    sw.insertTableEntry(**entry)

for mgid,ports in runtime_config.mcastGroups().iteritems():
    sw.addMulticastGroup(mgid=mgid, ports=ports)


net.pingAll()

subscriber1 = h1.popen('./subscriber.py 1234', stdout=sys.stdout, stderr=sys.stdout)
subscriber2 = h2.popen('./subscriber.py 1234', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.2)

h2.cmd('./publisher.py 10.255.255.255 1234')
time.sleep(0.2)

subscriber1.terminate()
subscriber2.terminate()
