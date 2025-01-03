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
from pox.lib.packet.icmp import icmp
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ETHER_BROADCAST
import struct
import socket

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

ECHO_REQUEST = 8 
ECHO_REPLY = 0

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

        if self._Block(packet, event) == 1:
            return

        if packet.type == ethernet.ARP_TYPE:
            self._Handle_arp(packet, event)
        elif packet.type == ethernet.IP_TYPE:
            self._Handle_ip(packet, event)
        else:
            log.info("Unhandled packet type: %s" % packet.type)
            print("Unhandled packet from %s" % packet.src)
    
    def _Block(self, packet, enent):
        # Chặn traffic không phù hợp 
        # Định danh địa chỉ MAC và IP nguồn, đích
        eth_src = str(packet.src)  
        eth_dst = str(packet.dst)  
        ip_packet = packet.payload if packet.type == ethernet.IP_TYPE else None
        # Nếu là gói tin IP, lấy thêm thông tin IP nguồn, IP đích
        if ip_packet and isinstance(ip_packet, ipv4):
            src_ip = str(ip_packet.srcip) 
            dst_ip = str(ip_packet.dstip) 
            protocol = ip_packet.protocol
            # Kiểm tra yêu cầu chặn
            if src_ip == "172.16.10.100": # Chăn gửi ICMP đến tất cả các host khác
                if dst_ip == "10.0.4.10":
                    # Chặn IP traffic đến serv1
                    log.info(f"[Blocked] [IP traffic] [hnotrust1 to {dst_ip}]")
                    return 1
                if protocol == ipv4.ICMP_PROTOCOL:
                    # Chặn ICMP đến các host khác
                    log.info(f"[Blocked] [ICMP traffic] [hnotrust1 to hosts]")
                    return 1
        return 0

    def _Handle_arp(self, packet, event):
        # Xử lí gói ARP
        arp_packet = packet.payload
        in_port = PORTS[str(arp_packet.protosrc)]
        dpid = self.connection.dpid
        # Cập nhật ARP Table
        self._Update_arp_table(event.dpid, str(arp_packet.protosrc), in_port, str(packet.src))
        log.info("[PACKET_IN] [ARP]")
        # Xử lí từng TH
        if arp_packet.opcode == arp.REQUEST:
            self._Deal_arp_request(event, arp_packet, in_port, packet, dpid)
        elif arp_packet.opcode == arp.REPLY:
            self._Deal_arp_reply(event, packet, arp_packet, in_port, dpid)

    def _Update_arp_table(self, dpid, ip, port, mac):
        if dpid not in self.arp_table:
            self.arp_table[dpid] = {}
        if ip not in self.arp_table[dpid]:
            self.arp_table[dpid][ip] = Entry(port, mac)
        log.info(" [ENTRY]-->[DPID] %s [IP] %s [PORT] %s [MAC] %s" % (dpid, ip, port, mac))

    def _Deal_arp_request(self, event, arp_packet, in_port, packet, dpid):
        log.info("----[ARP-REQUEST]")
        protodst = str(arp_packet.protodst)
        if protodst in self.arp_table[dpid]:
            prt = self.arpTable[dpid][protodst].port
            mac = EthAddr(self.arpTable[dpid][protodst].mac)
            # Thiết lập FLOW RULE
            # Tạo gói ARP Request và gửi đến các cổng đồng thời cập nhật FLOW RULE trong trường hợp biết thông tin trong ARP-Table
            r = arp()
            r.hwtype = r.HW_TYPE_ETHERNET
            r.prototype = r.PROTO_TYPE_IP
            r.hwlen = 6
            r.protolen = r.protolen
            r.opcode = r.REPLY
            r.hwdst = arp_packet.hwsrc
            r.protodst = arp_packet.protosrc
            r.hwsrc = mac
            r.protosrc = arp_packet.protosrc
            # Tạo gói Ethernet chứa ARP Request
            e = ethernet(type=ethernet.ARP_TYPE, src=mac, dst=arp_packet.hwsrc)
            # Đính kèm gói ARP
            e.set_payload(r)
            # Đóng gói và gửi gói tin ra cổng 
            msg = of.ofp_packet_out()
            msg.data = e.pack()
            msg.actions.append(of.ofp_action_output(port = prt))
            msg.in_port = in_port
            self.connection.send(msg)
        else:
            for host, ip in IPS.items():
                # Tạo gói ARP Request và gửi đến các cổng trong trường hợp chưa biết MAC đích 
                r = arp()
                r.hwtype = r.HW_TYPE_ETHERNET
                r.prototype = r.PROTO_TYPE_IP
                r.hwlen = 6
                r.protolen = 4
                r.opcode = r.REQUEST
                r.hwdst = ETHER_BROADCAST  # Gửi ARP Request đến tất cả các thiết bị trong mạng (broadcast)
                r.protodst = struct.unpack("!I", socket.inet_aton(ip))[0]
                r.hwsrc = packet.src 
                r.protosrc = arp_packet.protosrc 
                # Tạo gói Ethernet chứa ARP Request
                e = ethernet(type=ethernet.ARP_TYPE, src=packet.src, dst=ETHER_BROADCAST)
                # Đính kèm gói ARP
                e.set_payload(r)
                # Đóng gói và gửi gói tin ra cổng 
                msg = of.ofp_packet_out()
                msg.data = e.pack()  
                msg.actions.append(of.ofp_action_output(port=PORTS[ip])) 
                msg.in_port = in_port  
                self.connection.send(msg) 
            

    def _Deal_arp_reply(self, event, packet, arp_packet, in_port, dpid):
        log.info("----[ARP-REPLY]")
        dst_ip_str = str(arp_packet.protodst)
        # Cập nhật FLOW RULES
        protodst = str(arp_packet.protodst)
        prt = self.arp_table[dpid][protodst].port
        mac = EthAddr(self.arp_table[dpid][protodst].mac)
        actions = []
        actions.append(of.ofp_action_dl_addr.set_dst(mac))
        actions.append(of.ofp_action_output(port = prt))
        match = of.ofp_match.from_packet(packet, in_port)
        match.dl_src = None # Wildcard MAC
        msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=match)
        self.connection.send(msg.pack())
        # Tạo gói ARP Reply
        r = arp()
        r.hwtype = arp.HW_TYPE_ETHERNET
        r.prototype = arp.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = 4
        r.opcode = arp.REPLY  
        r.hwsrc = arp_packet.hwsrc  
        r.protosrc = struct.unpack("!I", socket.inet_aton(Gateway[dst_ip_str]))[0]  
        r.hwdst = arp_packet.hwdst  
        r.protodst = arp_packet.protodst  
        # Tạo gói Ethernet chứa ARP Reply
        e = ethernet()
        e.src = arp_packet.hwsrc 
        e.dst = arp_packet.hwdst  
        e.type = ethernet.ARP_TYPE
        # Đính kèm gói ARP Reply
        e.set_payload(r)  
        # Đóng gói và gửi gói tin qua cổng nhận ARP Request
        msg = of.ofp_packet_out()
        msg.data = e.pack() 
        msg.actions.append(of.ofp_action_output(port=PORTS[dst_ip_str]))
        msg.in_port = in_port
        self.connection.send(msg)

    def _Handle_ip(self, packet, event):
        # Xử lí gói IP
        ip_packet = packet.payload
        protocol_packet = ip_packet.payload
        dst_ip = ip_packet.dstip
        log.info("[PACKET_IN] [IP]")
        # Xử lí từng TH
        if ip_packet.protocol == ipv4.TCP_PROTOCOL:
            if str(dst_ip) in self.arp_table[self.connection.dpid]:
                log.info("----[TCP]")
                dst_mac = EthAddr(self.arp_table[self.connection.dpid][str(ip_packet.dstip)].mac)
                out_port = self.arp_table[self.connection.dpid][str(ip_packet.dstip)].port
                # Tạo gói Ethernet chứa ICMP
                e = ethernet()
                e.src = packet.src 
                e.dst = dst_mac 
                e.type = ethernet.IP_TYPE
                # Đính kèm gói ICMP Reply
                e.set_payload(ip_packet) 
                # Đóng gói và gửi gói tin qua cổng
                msg = of.ofp_packet_out()
                msg.data = e.pack() 
                msg.actions.append(of.ofp_action_output(port=out_port))
                msg.in_port = event.port
                self.connection.send(msg)
        if ip_packet.protocol == ipv4.ICMP_PROTOCOL:
            if protocol_packet.type == ECHO_REQUEST:
                if str(dst_ip) in self.arp_table[self.connection.dpid]:
                    log.info("----[ICMP-REQUEST]")
                    dst_mac = EthAddr(self.arp_table[self.connection.dpid][str(ip_packet.dstip)].mac)
                    out_port = self.arp_table[self.connection.dpid][str(ip_packet.dstip)].port
                    # Tạo gói Ethernet chứa ICMP
                    e = ethernet()
                    e.src = packet.src 
                    e.dst = dst_mac 
                    e.type = ethernet.IP_TYPE
                    # Đính kèm gói ICMP Reply
                    e.set_payload(ip_packet) 
                    # Đóng gói và gửi gói tin qua cổng
                    msg = of.ofp_packet_out()
                    msg.data = e.pack() 
                    msg.actions.append(of.ofp_action_output(port=out_port))
                    msg.in_port = event.port
                    self.connection.send(msg)
            if protocol_packet.type == ECHO_REPLY:
                if str(dst_ip) in self.arp_table[self.connection.dpid]:
                    log.info("----[ICMP-REPLY]")
                    dst_mac = EthAddr(self.arp_table[self.connection.dpid][str(ip_packet.dstip)].mac)
                    out_port = self.arp_table[self.connection.dpid][str(ip_packet.dstip)].port
                    # Tạo gói Ethernet chứa ICMP
                    e = ethernet()
                    e.src = packet.src  
                    e.dst = dst_mac  
                    e.type = ethernet.IP_TYPE
                    # Đính kèm gói tin ICMP Request
                    e.set_payload(ip_packet)  
                    # Đóng gói và gửi gói tin qua cổng
                    msg = of.ofp_packet_out()
                    msg.data = e.pack()  
                    msg.actions.append(of.ofp_action_output(port=out_port))  
                    msg.in_port = event.port
                    self.connection.send(msg)

def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
