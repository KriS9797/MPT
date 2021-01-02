from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

tcp_pkt = pkt.get_protocols(tcp.tcp)[0]

if tcp_pkt:
    if tcp.TCP_SYN and not tcp.TCP_ACK:
        # to do 

    elif tcp.TCP_SYN and tcp.TCP_ACK:
        # to do

    elif tcp.TCP_ACK and not tcp.TCP_SYN:
        # to do 
