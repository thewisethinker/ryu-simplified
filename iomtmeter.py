from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
import threading

table0 = 0;
table1 = 1; 
table2 = 2;

ovs_dpid = [302236120];
at_dpid = [115621926790];

video_ip = ["192.168.0.11","192.168.0.12","192.168.0.13"]

sensor_ip = ["192.168.0.6","192.168.0.8","192.168.0.9","192.168.0.12","192.168.0.13"]

broker_ip1 = ["192.168.0.12"]
broker_ip2 = ["192.168.0.13"]

#tos_sensor = 184; #46;
#tos_audvid = 136; #34;
#tos_others = 40; #10 AF11
dscp_sensor = 46; #EF
dscp_audvid = 34; #AF41
dscp_others = 10; #AF11 #40: CS5, 30: AF33
esp_macs = ["54:bf:64:a3:07:ee","58:bf:25:37:d9:10"];
esp_src = "ff:ff:ff:ff:ff:ff";
av_macs = ["54:bf:64:a3:07:ee"];
av_src = "ff:ff:ff:ff:ff:ff";

#rate1=2

'''
ip_pkt_tos_high=252

ip_pkt_tos_mid1=196
ip_pkt_tos_mid2=200
ip_pkt_tos_mid3=228
ip_pkt_tos_mid4=232
ip_pkt_tos_mid5=236
ip_pkt_tos_mid6=240
ip_pkt_tos_mid7=244
ip_pkt_tos_mid8=248

ip_pkt_tos_low=0
'''

class IoMTMeter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(IoMTMeter, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid=datapath.id
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match, actions, meter=None)
        
        #meter created using rest api due to ryu error of dscp remark band
       
        if dpid in ovs_dpid: #dpid of the OVS
            self.add_table0(datapath)
            self.add_table1(datapath)
            #self.table0_rules(datapath)
            self.createMeter(datapath,2000,1) #kbps 
            self.createMeter(datapath,500,2)
            self.table1_rules_bro1(datapath)
            self.table1_rules_bro2(datapath)
            self.table1_rules2(datapath)
            print("On dpid: %s",dpid)
            print("Creating Tables and Meters")
    
    def createMeter(self,datapath,rate1,meter_id):

        bands=[]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dropband=parser.OFPMeterBandDrop(rate=rate1, burst_size=1)
        bands.append(dropband)
        #remarked = parser.OFPMeterBandDscpRemark(rate=rate1,burst_size=0,prec_level=1) #it doesn't work
        #bands.append(remarked)

        request=parser.OFPMeterMod(datapath=datapath,
                                command=ofproto.OFPMC_ADD,
                                flags=ofproto.OFPMF_KBPS,
                                meter_id=meter_id,
                                bands=bands)

        datapath.send_msg(request)
        self.logger.info("New Meter Created on Switch: %s with ID: %s", datapath.id,meter_id)
        

    def add_table0(self, datapath): 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(table1)]    
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table0, priority=1000, instructions=inst)
        datapath.send_msg(mod)

    def add_table1(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out_port = ofproto.OFPP_FLOOD
        #priority=1
        actions = [parser.OFPActionOutput(out_port)]  
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table1, priority=1000, instructions=inst)
        datapath.send_msg(mod)
    
      
    def table1_rules_bro1(self, datapath):
        ofproto = datapath.ofproto
	
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src="192.168.0.12")#, ip_proto=in_proto.IPPROTO_TCP)
        out_port = ofproto.OFPP_FLOOD
        #priority=1
        actions = [parser.OFPActionSetField(ip_dscp=46), parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]			
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table1, priority=3000, match=match, instructions=inst)
	    
        datapath.send_msg(mod)
        print("table1 for sensor traffic: %s", mod)

    def table1_rules_bro2(self, datapath):
        ofproto = datapath.ofproto
	
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src="192.168.0.13")#, ip_proto=in_proto.IPPROTO_TCP)
        out_port = ofproto.OFPP_FLOOD
        #priority=1
        actions = [parser.OFPActionSetField(ip_dscp=46), parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]			
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table1, priority=3000, match=match, instructions=inst)
	    
        datapath.send_msg(mod)
        print("table1 for sensor traffic: %s", mod)

    def table1_rules2(self, datapath):
        ofproto = datapath.ofproto
	
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)#, ip_proto=in_proto.IPPROTO_TCP)
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionSetField(ip_dscp=10), parser.OFPActionOutput(out_port)]
        
        #priority=1
        #actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionMeter(2), parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        			
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table1, priority=2000, match=match, instructions=inst)
	    
        datapath.send_msg(mod)
        print("table1 for sensor traffic: %s", mod)
 
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, meter=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match, table_id=table0,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, table_id=table0, instructions=inst)

        datapath.send_msg(mod)
        print("inside add flow")

 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
      
        print("inside packetin handler")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                            ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        #if eth.ethertype == ether_types.ETH_TYPE_IP:
        #    self.table0_rules(datapath)
        #    self.table1_rules(datapath)
              

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
        
        #priority=1
        actions = [parser.OFPActionOutput(out_port)]
        
      
        # install a flow to avoid packet_in next time
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 100, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 100, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)