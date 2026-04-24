#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp, icmp, ether_types


class PortStatusMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PortStatusMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port_packet_count = {}
        self.logger.info("=" * 78)
        self.logger.info("PORT STATUS MONITORING TOOL STARTED")
        self.logger.info("=" * 78)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id is not None:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                instructions=inst,
            )

        datapath.send_msg(mod)

    def _port_state_text(self, state, ofproto):
        flags = []
        if state & ofproto.OFPPS_LINK_DOWN:
            flags.append("LINK_DOWN")
        if state & ofproto.OFPPS_BLOCKED:
            flags.append("BLOCKED")
        if state & ofproto.OFPPS_LIVE:
            flags.append("LIVE")
        return ",".join(flags) if flags else "UP"

    def _decode_port_name(self, port_name):
        if isinstance(port_name, bytes):
            return port_name.decode("utf-8", errors="ignore").strip("\x00")
        return str(port_name)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.mac_to_port.setdefault(datapath.id, {})
        self.port_packet_count.setdefault(datapath.id, {})

        self.logger.info("-" * 78)
        self.logger.info("Switch connected | dpid=%s", datapath.id)
        self.logger.info("Table-miss flow installed")
        self.logger.info("-" * 78)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        reason_map = {
            ofproto.OFPPR_ADD: "ADD",
            ofproto.OFPPR_DELETE: "DELETE",
            ofproto.OFPPR_MODIFY: "MODIFY",
        }

        reason = reason_map.get(msg.reason, str(msg.reason))
        port = msg.desc
        port_name = self._decode_port_name(port.name)
        state_text = self._port_state_text(port.state, ofproto)

        self.logger.info("=" * 78)
        self.logger.info(
            "PORT STATUS | dpid=%s | port=%s | name=%s | reason=%s | state=%s",
            datapath.id,
            port.port_no,
            port_name,
            reason,
            state_text,
        )
        self.logger.info("=" * 78)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.port_packet_count.setdefault(dpid, {})
        self.port_packet_count[dpid][in_port] = self.port_packet_count[dpid].get(in_port, 0) + 1

        src = eth.src
        dst = eth.dst
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            self.logger.info(
                "[PACKET] dpid=%s | in_port=%s | ARP | src_mac=%s | dst_mac=%s | op=%s | port_hits=%s",
                dpid,
                in_port,
                src,
                dst,
                arp_pkt.opcode,
                self.port_packet_count[dpid][in_port],
            )
        elif ip_pkt:
            l4_proto = "IP"
            src_l4 = "-"
            dst_l4 = "-"

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            icmp_pkt = pkt.get_protocol(icmp.icmp)

            if tcp_pkt:
                l4_proto = "TCP"
                src_l4 = tcp_pkt.src_port
                dst_l4 = tcp_pkt.dst_port
            elif udp_pkt:
                l4_proto = "UDP"
                src_l4 = udp_pkt.src_port
                dst_l4 = udp_pkt.dst_port
            elif icmp_pkt:
                l4_proto = "ICMP"

            self.logger.info(
                "[PACKET] dpid=%s | in_port=%s | %s | %s:%s -> %s:%s | src_mac=%s | dst_mac=%s | port_hits=%s",
                dpid,
                in_port,
                l4_proto,
                ip_pkt.src,
                src_l4,
                ip_pkt.dst,
                dst_l4,
                src,
                dst,
                self.port_packet_count[dpid][in_port],
            )
        else:
            self.logger.info(
                "[PACKET] dpid=%s | in_port=%s | eth_type=0x%04x | src_mac=%s | dst_mac=%s | port_hits=%s",
                dpid,
                in_port,
                eth.ethertype,
                src,
                dst,
                self.port_packet_count[dpid][in_port],
            )

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)