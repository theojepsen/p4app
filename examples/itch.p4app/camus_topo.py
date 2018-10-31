from mininet.topo import Topo

def getPort(link, node): return link['port1'] if link['node1'] == node else link['port2']

class CamusTopo(Topo):
    """ Abstract topology routing using Camus.
        Assumes that each host is connected to exactly one switch.
    """

    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        self.subscriptions_for_sw = {}
        self.rules_for_sw = {}

    def hostSwitch(self, host):
        """ Return edge switch to which `host` is connected """
        for a,b in self.links():
            if host == a and self.isSwitch(b):
                return b
            if host == b and self.isSwitch(a):
                return a
        raise Exception("Could not find a link to any switch from host %s" % host)

    def switchPortForHost(self, host):
        """ Return the switch port to which `host` is connected """
        switch = self.hostSwitch(host)
        return getPort(self.linkInfo(host, switch), switch)

    def subscribe(self, host, queries):
        if isinstance(queries, basestring):
            queries = [queries]

        switch = self.hostSwitch(host)
        self.addSubscriptionRec(host, queries, switch, self.linkInfo(host, switch))

    def addSubscriptionRec(self, host, queries, switch, down_link):
        raise NotImplementedError()

class SingleSwitchTopo(CamusTopo):
    def __init__(self, n, **opts):
        CamusTopo.__init__(self, **opts)

        switch = self.addSwitch('s1')
        self.rules_for_sw['s1'] = []

        for i in xrange(1, n+1):
            host = self.addHost('h%d' % i,
                                ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)

    def addSubscriptionRec(self, host, queries, switch, down_link):
        port = getPort(down_link, switch)
        for q in queries:
            self.rules_for_sw[switch].append('%s: fwd(%d);' % (q, port))

