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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        empty_match = parser.OFPMatch()
        instructions = []
	print "making delete mod"
        flow_mod = parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_DELETE,
                                               0, 0, 1, ofproto.OFPCML_NO_BUFFER,
                                               ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                               0, empty_match, instructions)
        print "deleting all flow entries in table ", 0
        datapath.send_msg(flow_mod)
        flow_mod = parser.OFPFlowMod(datapath, 0, 0, 1, ofproto.OFPFC_DELETE,
                                               0, 0, 1, ofproto.OFPCML_NO_BUFFER,
                                               ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                               0, empty_match, instructions)
        print "deleting all flow entries in table ", 1
        datapath.send_msg(flow_mod)

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, table_id=0)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, table_id=1)
        # install flow to flood broadcast packets
        match = parser.OFPMatch(eth_dst = ("01:00:00:00:00:00", "01:00:00:00:00:00"))
        actions = [parser.OFPActionOutput(ofproto.OFPP_ALL)]
        self.add_flow(datapath, 1, match, actions, table_id=1)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=table_id)
        datapath.send_msg(mod)

    def add_flow_instructions(self, datapath, priority, match, instructions, buffer_id=None, table_id=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=instructions, table_id=table_id)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=instructions, table_id=table_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
            #out_port = ofproto.OFPP_FLOOD
            out_port = ofproto.OFPP_ALL
        actions_out = [parser.OFPActionOutput(in_port)]
        actions_flood = [parser.OFPActionOutput(out_port)]
        instructions_out =  [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions_out)]
        instructions_next_table = [parser.OFPInstructionGotoTable(1)]
        #actions = [parser.OFPActionOutput(out_port)]
        match_src = parser.OFPMatch(in_port=in_port, eth_src=src)
        match_dst = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        match_src_dst = parser.OFPMatch(eth_dst=src)
        self.add_flow_instructions(datapath, 1, match_src, instructions_next_table, table_id=0)
        self.add_flow_instructions(datapath, 1, match_src_dst, instructions_out, table_id=1)
        
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and out_port != ofproto.OFPP_ALL:
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                #self.add_flow_instructions(datapath, 1, match_dst, instructions_out, msg.buffer_id, table_id=1)
                return
            else:
                #self.add_flow_instructions(datapath, 1, match_dst, instructions_out, table_id=1)
                pass
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions_flood, data=data)
        datapath.send_msg(out)
