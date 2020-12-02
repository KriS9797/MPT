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
        host_a1 = self.addHost( 'h1' )
        host_a2 = self.addHost( 'h2' )
        host_a3 = self.addHost( 'h3' )
        host_1 = self.addHost( 'h4' )
        host_2 = self.addHost( 'h5' )
        host_3 = self.addHost( 'h6' )
        server_1 = self.addHost( 'h7' )
        server_2 = self.addHost( 'h8' )
        server_3 = self.addHost( 'h9' )
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



topos = { 'mytopo': ( lambda: MyTopo() ) }
