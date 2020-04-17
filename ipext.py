# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#Edited by N. Medhi
#Extracting the IPv4 header

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct


from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
                                                 
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from scapy.all import rdpcap
from collections import Counter
import struct
import serial
import os


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
	
	ipv4_header = pkt.get_protocol(ipv4.ipv4)
        arp_head = pkt.get_protocol(arp.arp)
	
	src_ip = ""
	dst_ip = ""
	src_ipv4 = ""
	dst_ipv4 = "" 	
	
	if arp_head:
	    src_ip = arp_head.src_ip #ipv4_header.src  #ipv4.ipv4(src) # ipv4_header.src_ip
            dst_ip = arp_head.dst_ip #ipv4_header.dst  #ipv4.ipv4(dst) # ipv4_header.dst_ip	
	elif ipv4_header:
	    src_ipv4 = ipv4_header.src
	    dst_ipv4 = ipv4_header.dst
	else:
	    pass

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("\npacket in DPID: %s, \nsource MAC: %s, dest MAC: %s, \nARP_SRC_IP: %s, ARP_DST_IP: %s, \nv4_src_ip: %s, v4_dst_ip: %s, \ninput_port: %s", dpid, src, dst, str(src_ip), str(dst_ip), src_ipv4, dst_ipv4, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        #actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
	actions= []	
	
	mac_to_block = []
	blocked_ip=["10.0.0.1"]
	for i in blocked_ip:
	    if i == src_ip:
		mac_to_block.append(src)
	
	   
		
        print(mac_to_block)
        for e in mac_to_block:
            if e == src:
                actions = []
                break
            else:
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY: 
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
