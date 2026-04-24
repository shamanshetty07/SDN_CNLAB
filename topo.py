#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class PortStatusTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


def run():
    topo = PortStatusTopo()
    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSKernelSwitch,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    c0 = RemoteController("c0", ip="127.0.0.1", port=6633)
    net.addController(c0)

    info("\n*** Starting network\n")
    net.start()

    info("\n*** Topology loaded. Try: pingall, iperf, link down/up\n")
    CLI(net)

    info("\n*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()