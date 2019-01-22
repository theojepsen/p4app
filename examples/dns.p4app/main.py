from p4app import P4Mininet, P4Program
from mininet.topo import SingleSwitchTopo

def str_to_hex(s, width):
    out = '0x'
    for i in range(width):
        if i < len(s): out += '%x' % ord(s[i])
        else: out += '00'
    return out

hostname = 'service1'
ip = '10.0.0.2'

topo = SingleSwitchTopo(2)
prog = P4Program('dns.p4', version=14)
net = P4Mininet(program=prog, topo=topo)
net.start()

s1 = net.get('s1')
s1.command('table_add dns_host answerDNS %s => %s' % (str_to_hex(hostname, 8), ip))

h1 = net.get('h1')
h1.cmd('echo nameserver 10.0.0.2 > /etc/resolv.conf')
#proc = h1.popen('dig +short +tries=0 +time=1 @10.0.0.2 %s' % hostname) # requires dnsutils
proc = h1.popen('ping -c2 %s' % hostname)
stdout, stderr = proc.communicate()
print stdout, stderr
assert proc.returncode == 0
