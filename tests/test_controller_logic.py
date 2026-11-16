#!/usr/bin/env python3
"""
Offline unit test of firewall_controller.py (no Mininet / root needed).
It feeds hand-built packet-in events to the controller with a fake datapath
and checks which OpenFlow messages and alerts come out.

    python3 tests/test_controller_logic.py        (needs `ryu` importable)
"""
import os
import sys
import time
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ["FW_MODE"] = "dynamic"
os.environ["FW_SYN_THRESHOLD"] = "5"
os.environ["FW_BLOCK_TIMEOUT_S"] = "7"

import config                                              # noqa: E402
import firewall_controller as fc                           # noqa: E402
from ryu.lib.packet import ethernet, ipv4, packet, tcp, arp  # noqa: E402
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser  # noqa: E402


class FakeDP:
    id = 1
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self):
        self.sent = []

    def send_msg(self, m):
        self.sent.append(m)


def mac(ip):
    return {"10.0.0.1": "00:00:00:00:00:01", "10.0.0.3": "00:00:00:00:00:03",
            "10.0.0.10": "00:00:00:00:00:10", "10.0.0.100": "00:00:00:00:01:00"}[ip]


def tcp_pkt(src, dst, sport, dport, bits=tcp.TCP_SYN):
    p = packet.Packet()
    p.add_protocol(ethernet.ethernet(dst=mac(dst), src=mac(src), ethertype=0x0800))
    p.add_protocol(ipv4.ipv4(src=src, dst=dst, proto=6))
    p.add_protocol(tcp.tcp(src_port=sport, dst_port=dport, bits=bits))
    p.serialize()
    return p.data


def pin(dp, data, in_port):
    msg = types.SimpleNamespace(datapath=dp, data=data, match={"in_port": in_port},
                                buffer_id=ofproto_v1_3.OFP_NO_BUFFER)
    return types.SimpleNamespace(msg=msg)


class Controller(unittest.TestCase):
    def setUp(self):
        self.app = fc.SDNFirewall()
        self.alerts = []
        self.app._alert = lambda event, ts=None, **f: self.alerts.append((event, f))
        self.dp = FakeDP()
        # learn the hosts' ports
        self.app.mac_to_port[1] = {mac("10.0.0.10"): 10, mac("10.0.0.1"): 1, mac("10.0.0.3"): 3}

    def flows(self, prio):
        return [m for m in self.dp.sent if isinstance(m, ofproto_v1_3_parser.OFPFlowMod)
                and m.priority == prio]

    def test_classify(self):
        self.assertEqual(fc.classify("10.0.0.1", "10.0.0.10", 5000)[0], "ALLOW")
        self.assertEqual(fc.classify("10.0.0.1", "10.0.0.10", 6000)[0], "DENY")
        self.assertEqual(fc.classify("10.0.0.1", "10.0.0.10", 22)[0], "DENY")
        self.assertEqual(fc.classify("10.0.0.1", "10.0.0.100", 9999)[0], "DENY")
        self.assertEqual(fc.classify("10.0.0.1", "10.0.0.2", 80)[0], "ALLOW")

    def test_allowed_connection_installs_both_directions(self):
        self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.1", "10.0.0.10", 40000, 5000), 1))
        self.assertEqual(len(self.flows(fc.PRIO_ALLOW_TCP)), 2)
        self.assertEqual([a[0] for a in self.alerts], ["ALLOW"])

    def test_restricted_port_denied(self):
        self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.1", "10.0.0.10", 40000, 6000), 1))
        self.assertEqual(len(self.flows(fc.PRIO_DENY)), 1)
        self.assertEqual(len(self.flows(fc.PRIO_ALLOW_TCP)), 0)
        self.assertEqual(self.alerts[0][0], "DENY")

    def test_syn_flood_is_blocked_with_timeout_and_alert(self):
        for i in range(5):
            self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.3", "10.0.0.10", 41000 + i, 5000), 3))
        blocks = self.flows(fc.PRIO_BLOCK)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0].hard_timeout, 7)
        self.assertTrue(blocks[0].flags & ofproto_v1_3.OFPFF_SEND_FLOW_REM)
        self.assertEqual(blocks[0].instructions, [])          # drop
        ev = [a for a in self.alerts if a[0] == "BLOCK"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0][1]["src_ip"], "10.0.0.3")
        self.assertIn("first_seen_ts", ev[0][1])
        self.assertEqual(ev[0][1]["timeout"], 7)
        # the 5th SYN (trigger) must not be forwarded
        self.assertEqual(len(self.flows(fc.PRIO_ALLOW_TCP)), 2 * 4)

    def test_normal_rate_not_blocked(self):
        for i in range(4):
            self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.1", "10.0.0.10", 42000 + i, 5000), 1))
        self.assertEqual(len(self.flows(fc.PRIO_BLOCK)), 0)

    def test_repeated_denials_escalate_to_block(self):
        for i in range(config.DENY_ESCALATE_COUNT):
            self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.3", "10.0.0.10", 43000 + i, 6000), 3))
        self.assertEqual(len(self.flows(fc.PRIO_BLOCK)), 1)
        reasons = [a[1]["reason"] for a in self.alerts if a[0] == "BLOCK"]
        self.assertTrue(reasons and "unauthorised" in reasons[0])

    def test_flow_removed_triggers_unblock(self):
        for i in range(5):
            self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.3", "10.0.0.10", 44000 + i, 5000), 3))
        self.assertIn("10.0.0.3", self.app.blocked)
        m = types.SimpleNamespace(
            cookie=fc.BLOCK_COOKIE, datapath=self.dp, reason=ofproto_v1_3.OFPRR_HARD_TIMEOUT,
            match=ofproto_v1_3_parser.OFPMatch(eth_type=0x0800, ipv4_src="10.0.0.3"))
        self.app._flow_removed(types.SimpleNamespace(msg=m))
        self.assertNotIn("10.0.0.3", self.app.blocked)
        self.assertEqual(self.alerts[-1][0], "UNBLOCK")
        # after recovery the host is treated normally again
        self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.3", "10.0.0.10", 45000, 5000), 3))
        self.assertGreaterEqual(len(self.flows(fc.PRIO_ALLOW_TCP)), 2)

    def test_exempt_hosts_never_blocked(self):
        for i in range(20):
            self.app._packet_in(pin(self.dp, tcp_pkt("10.0.0.10", "10.0.0.1", 5000 + i, 40000 + i), 10))
        self.assertEqual(len(self.flows(fc.PRIO_BLOCK)), 0)

    def test_arp_is_flooded_not_dropped(self):
        p = packet.Packet()
        p.add_protocol(ethernet.ethernet(dst="ff:ff:ff:ff:ff:ff", src=mac("10.0.0.1"), ethertype=0x0806))
        p.add_protocol(arp.arp(src_mac=mac("10.0.0.1"), src_ip="10.0.0.1",
                               dst_mac="00:00:00:00:00:00", dst_ip="10.0.0.10"))
        p.serialize()
        self.app._packet_in(pin(self.dp, p.data, 1))
        outs = [m for m in self.dp.sent if isinstance(m, ofproto_v1_3_parser.OFPPacketOut)]
        self.assertEqual(len(outs), 1)
        self.assertEqual(outs[0].actions[0].port, ofproto_v1_3.OFPP_FLOOD)


class StaticMode(unittest.TestCase):
    def test_static_never_blocks(self):
        os.environ["FW_MODE"] = "static"
        try:
            app = fc.SDNFirewall()
        finally:
            os.environ["FW_MODE"] = "dynamic"
        app._alert = lambda *a, **k: None
        dp = FakeDP()
        app.mac_to_port[1] = {mac("10.0.0.10"): 10, mac("10.0.0.3"): 3}
        for i in range(50):
            app._packet_in(pin(dp, tcp_pkt("10.0.0.3", "10.0.0.10", 46000 + i, 5000), 3))
        blocks = [m for m in dp.sent if getattr(m, "priority", None) == fc.PRIO_BLOCK]
        self.assertEqual(blocks, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
