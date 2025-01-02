# Part 4 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ETHER_BROADCAST

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}

Gateway = {
    "10.0.1.10": "10.0.1.1",
    "10.0.2.20": "10.0.2.1",
    "10.0.3.30": "10.0.3.1",
    "10.0.4.10": "10.0.4.1",
    "172.16.10.100": "172.16.10.1"
}

PORTS = {
    "10.0.1.10": 1,
    "10.0.2.20": 2,
    "10.0.3.30": 3,
    "10.0.4.10": 4,
    "172.16.10.100": 5
}

FLOW_IDLE_TIMEOUT = 10

class Entry:
    def __init__(self, port, mac):
        self.port = port
        self.mac = mac

class Part4Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection
        self.arp_table = {}  # ARP table to store IP to MAC mappings

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    def s1_setup(self):
        self._Allow_all_path()

    def s2_setup(self):
        self._Allow_all_path()

    def s3_setup(self):
        self._Allow_all_path()

    def cores21_setup(self):
        self._Block()

        # Controller xử lí gói ICMP, ARP
        flow_mod = of.ofp_flow_mod()
        flow_mod.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(flow_mod)

    def dcs31_setup(self):
        self._Allow_all_path()

    # Flood gói tin đến các cổng khác
    def _Allow_all_path(self):
        flow_mod = of.ofp_flow_mod()
        flow_mod.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(flow_mod)

    # Chặn 
    def _Block(self):
        src_ip = IPS['hnotrust']
        dst_ip = IPS['serv1']

        block_icmp = of.ofp_flow_mod(
            priority=20,
            match=of.ofp_match(dl_type=0x800, nw_proto=pkt.ipv4.ICMP_PROTOCOL, nw_src=src_ip)
        )
        self.connection.send(block_icmp)

        block_to_serv = of.ofp_flow_mod(
            priority=19,
            match=of.ofp_match(dl_type=0x800, nw_src=src_ip, nw_dst=dst_ip)
        )
        self.connection.send(block_to_serv)

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """
        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        if packet.type == ethernet.ARP_TYPE:
            self._Handle_arp(packet, event)
        elif packet.type == ethernet.IP_TYPE:
            self._Handle_ip(packet, event)
        else:
            log.info("Unhandled packet type: %s" % packet.type)
            print("Unhandled packet from %s" % packet.src)

    def _Handle_arp(self, packet, event):
        """Handle ARP packets."""

        arp_packet = packet.payload
        in_port = PORTS[str(arp_packet.protosrc)]
        dpid = self.connection.dpid

        self._Update_arp_table(event.dpid, arp_packet.protosrc,
                                in_port, packet.src)
        log.info("Checking info ARP: " +packet.dump())

        if arp_packet.opcode == arp.REQUEST:
            self._Deal_arp_request(event, arp_packet, in_port, 
                                    packet, dpid)
        elif arp_packet.opcode == arp.REPLY:
            self._Deal_arp_reply(event, arp_packet, in_port)

    def _Update_arp_table(self, dpid, ip, port, mac):
        if dpid not in self.arp_table:
            self.arp_table[dpid] = {}
        if ip not in self.arp_table[dpid]:
            self.arp_table[dpid][ip] = Entry(port, mac)
        log.info("------>Installing entry on dpid %s for %s with port %s, mac %s " % (dpid, ip, port, mac))

    def dpid_to_mac(self,dpid):
        return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


    def _Deal_arp_request(self, event, arp_packet, in_port, packet, dpid):
        protodst = arp_packet.protodst
        if protodst in self.arp_table[dpid]:
            log.info("Dealing with ARP request ---> 1")

            prt = self.arpTable[dpid][protodst].port
            mac = self.arpTable[dpid][protodst].mac
            
            actions = []
            actions.append(of.ofp_action_dl_addr.set_dst(mac))
            actions.append(of.ofp_action_output(port = prt))
            match = of.ofp_match.from_packet(packet, in_port)
            match.dl_src = None # Wildcard source MAC
            
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                    idle_timeout=FLOW_IDLE_TIMEOUT,
                                    hard_timeout=of.OFP_FLOW_PERMANENT,
                                    buffer_id=event.ofp.buffer_id,
                                    actions=actions,
                                    match=of.ofp_match.from_packet(packet, in_port))
            self.connection.send(msg.pack())
        elif str(protodst) in Gateway[str(arp_packet.protosrc)]:
            a = packet.next
            r = pkt.arp()
            r.hwtype = a.hwtype
            r.prototype = a.prototype
            r.hwlen = a.hwlen
            r.protolen = a.protolen
            r.opcode = pkt.arp.REPLY
            r.hwdst = a.hwsrc
            r.protodst = a.protosrc
            r.protosrc = a.protodst
            r.hwsrc = self.dpid_to_mac(dpid)
            e = pkt.ethernet(type=packet.type, src=self.dpid_to_mac(dpid), dst=a.hwsrc)
            e.set_payload(r)
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
            msg.in_port = event.port
            self._Update_arp_table(dpid, r.protosrc, event.port, r.hwsrc)
            self.connection.send(msg)

            actions = []
            actions.append(of.ofp_action_dl_addr.set_dst(r.hwdst))
            actions.append(of.ofp_action_output(port = event.port))
            match = of.ofp_match.from_packet(packet, in_port)
            match.dl_src = None # Wildcard source MAC
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                    idle_timeout=FLOW_IDLE_TIMEOUT,
                                    hard_timeout=of.OFP_FLOW_PERMANENT,
                                    buffer_id=event.ofp.buffer_id,
                                    actions=actions,
                                    match=of.ofp_match.from_packet(packet, in_port))
            self.connection.send(msg.pack())
        else:
            r = arp()
            r.hwtype = r.HW_TYPE_ETHERNET
            r.prototype = r.PROTO_TYPE_IP
            r.hwlen = 6
            r.protolen = r.protolen
            r.opcode = r.REQUEST
            r.hwdst = ETHER_BROADCAST
            r.protodst = arp_packet.protodst
            r.hwsrc = packet.src
            r.protosrc = arp_packet.protosrc
            e = ethernet(type=ethernet.ARP_TYPE, src=packet.src, dst=ETHER_BROADCAST)
            e.set_payload(r)
            log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, in_port,
            str(r.protodst), str(r.protosrc)))
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.in_port = in_port
            self._Update_arp_table(dpid, r.protosrc, in_port, r.hwsrc)
            self.connection.send(msg)

    def _Deal_arp_reply(self, event, arp_packet, in_port):
        if arp_packet.protodst in self.arp_table[self.connection.dpid]:
            prt = self.arpTable[self.connection.dpid][arp_packet.protodst].port
            mac = self.arpTable[self.connection.dpid][arp_packet.protodst].mac
            
            actions = []
            actions.append(of.ofp_action_dl_addr.set_dst(mac))
            actions.append(of.ofp_action_output(port = prt))
            match = of.ofp_match.from_packet(packet, in_port)
            match.dl_src = None # Wildcard source MAC
            
            msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                    idle_timeout=FLOW_IDLE_TIMEOUT,
                                    hard_timeout=of.OFP_FLOW_PERMANENT,
                                    buffer_id=event.ofp.buffer_id,
                                    actions=actions,
                                    match=of.ofp_match.from_packet(packet, in_port))
            
            self.connection.send(msg.pack())

    def _Handle_ip(self, packet, event):
        ip_packet = packet.payload
        dst_ip = ip_packet.dstip

        log.info("Checking info ARP: " +packet.dump())

        if dst_ip in self.arp_table[self.connection.dpid]:
            dst_mac = self.arp-table[self.connection.dpid][ip_packet.protodst].mac
            out_port = self.arp_table[self.connection.dpid][ip_packet.protodst].port
            self.forward_packet(packet, event.ofp, out_port)

    def forward_packet(self, packet, packet_in, out_port):
        """Forward the packet to the specified port."""
        msg = of.ofp_packet_out()
        msg.data = packet_in
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)


def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
