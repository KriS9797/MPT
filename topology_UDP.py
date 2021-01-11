"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host_a1 = self.addHost( 'h1', ip='10.0.0.1/24' )
        host_a2 = self.addHost( 'h2', ip='10.0.0.2/24' )
        host_a3 = self.addHost( 'h3', ip='10.0.0.3/24' )
        host_1 = self.addHost( 'h4', ip='10.0.0.4/24' )
        host_2 = self.addHost( 'h5', ip='10.0.0.5/24' )
        host_3 = self.addHost( 'h6', ip='10.0.0.6/24' )
        server_1 = self.addHost( 'h7', ip='10.0.0.7/24' )
        server_2 = self.addHost( 'h8', ip='10.0.0.8/24' )
        server_3 = self.addHost( 'h9', ip='10.0.0.9/24' )
        switch = self.addSwitch( 's1' )

        # Add links
        self.addLink( host_a1, switch, cls=TCLink, bw=2)
        self.addLink( host_a2, switch, cls=TCLink, bw=2)
        self.addLink( host_a3, switch, cls=TCLink, bw=2)
        self.addLink( host_1, switch, cls=TCLink, bw=0.2)
        self.addLink( host_2, switch, cls=TCLink, bw=0.2)
        self.addLink( host_3, switch, cls=TCLink, bw=0.2) 
        self.addLink( switch, server_1, cls=TCLink, bw=0.5)
        self.addLink( switch, server_2, cls=TCLink, bw=0.5)
        self.addLink( switch, server_3, cls=TCLink, bw=0.5)

        host_1.cmd("iperf -s -u -p 80 -i 1 &")
        host_2.cmd("iperf -s -u -p 53 -i 1 &")        
        host_3.cmd("iperf -s -u -p 10 -i 1 &")
        host_a1.cmd("hping3 -c 10000 -i u10 -d 150 -S -p 80 --flood 10.0.0.4")
        host_a2.cmd("hping3 -c 10000 -i u10 -d 150 -S -p 53 --flood 10.0.0.5")        
        host_a3.cmd("hping3 -c 10000 -i u10 -d 150 -S -p 10 --flood 10.0.0.6")
        server_1.cmd(" iperf -c 10.0.0.1 -p 80 -u -t 15 &")
        server_2.cmd(" iperf -c 10.0.0.2 -p 53 -u -t 15 &")        
        server_3.cmd(" iperf -c 10.0.0.3 -p 10 -u -t 15 &")
        
topos = { 'mytopo': ( lambda: MyTopo() ) }
