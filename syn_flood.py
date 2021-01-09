# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4


class SimpleSwitch12(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch12, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.AttackDict = [{'src_ip': '', 'attack_counter': 0}]
        self.SYN_Received = [{'dst_ip': '', 'src_ip': '', 'seq': '', 'attack': 0}]
        self.SYNACK_Received = [{'dst_ip': '', 'src_ip': '', 'seq': '', 'ack': ''}]

    def in_dictlist(self, key, value, my_dictlist):
        for this in my_dictlist:
            if this[key] == value:
                return this

    def check_value(self, key1, value1, key2, my_dictlist):
        for this in my_dictlist:
            if this[key1] == value1:
                return this[key2]
        return {}

    def change_value(self, key1, value1, key2, value2, my_dictlist):
        for this in my_dictlist:
            if this[key1] == value1:
                this[key2] = value2
        return {}

    def increase_attack_counter(self, ip_key, ip_value, counter, my_dictlist):
        for this in my_dictlist:
            if this[ip_key] == ip_value:
                this[counter] += 1
        return {}

    def add_flow(self, datapath, port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst,
                                                 eth_src=src)
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
	
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
########################################################################################

        pkt_ipv4 = pkt.get_protocols(ipv4.ipv4)
        attack=0
        tcp_pkt = pkt.get_protocols(tcp.tcp)

        if tcp_pkt:
            self.logger.info("TCPPPPPPP")
            tcp_pkt = tcp_pkt[0]
            src_ip = pkt_ipv4[0].src
            dst_ip = pkt_ipv4[0].dst
            seq = tcp_pkt.seq
            ack = tcp_pkt.ack
            self.logger.info(tcp_pkt.has_flags(tcp.TCP_SYN))
            self.logger.info(tcp_pkt.has_flags(tcp.TCP_ACK))

            if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
                if self.in_dictlist('src_ip', src_ip, self.AttackDict):
                    self.logger.info("TUUUTAJ")
                    self.increase_attack_counter('src_ip', src_ip, 'attack_counter', self.AttackDict)
                else:
                    self.AttackDict.append({'src_ip': src_ip, 'attack_counter': 1})
                self.SYN_Received.append({
                    'dst_ip': dst_ip,
                    'src_ip': src_ip,
                    'seq': seq,
                    'ack': ack,
                    'attack': attack
                    })

                current_counter_value = self.check_value('src_ip', src_ip, 'attack_counter', self.AttackDict)
                self.logger.info(current_counter_value)
                if current_counter_value == 10:
                    self.change_value('src_ip', src_ip, 'attack', 1, self.SYN_Received)

                is_attack = self.check_value('src_ip', src_ip, 'attack', self.SYN_Received)

                if is_attack == 1:
                    self.logger.info("ATTTTTTTTTTTTTTTTTTTAAAAAAAAAAAAAAAAACKKKKKKKKKKKKK")

                    # < dodać wpis, żeby dropowało pakiety >

            elif tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_ACK):
                self.logger.info("1")
                self.logger.info(self.in_dictlist('dst_ip', src_ip, self.SYN_Received))
                if self.in_dictlist('dst_ip', src_ip, self.SYN_Received):
                    self.logger.info("2")
                    previous_seq = self.check_value('dst_ip', src_ip, 'seq', self.SYN_Received)
                    if ack == previous_seq + 1:
                        self.SYNACK_Received.append({
                        'dst_ip': dst_ip,
                        'src_ip': src_ip,
                        'seq': seq,
                        'ack': ack
                    })

            elif not tcp_pkt.has_flags(tcp.TCP_SYN) and tcp_pkt.has_flags(tcp.TCP_ACK):
                self.logger.info("TUTAJ")
                if self.in_dictlist('dst_ip', src_ip, self.SYNACK_Received):
                    self.logger.info("2")
                    previous_seq = self.check_value('dst_ip', src_ip, 'seq', self.SYNACK_Received)
                    previous_ack = self.check_value('dst_ip', src_ip, 'ack', self.SYNACK_Received)
                    if ack == previous_seq + 1:
                        if seq == previous_ack:
                            self.add_flow(datapath, in_port, dst, src, actions)
                            self.logger.info("FLOW DODANY")
                            # pass
                            # < dodać wpis żeby forwardowało pakiety >

###############################################################
        # install a flow to avoid packet_in next time
        # if out_port != ofproto.OFPP_FLOOD:
        #     self.add_flow(datapath, in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
