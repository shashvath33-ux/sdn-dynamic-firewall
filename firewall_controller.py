#!/usr/bin/env python3
"""
Dynamic SDN firewall  (Project 1 - Part 3)   Ryu, OpenFlow 1.3

Reactive learning switch + TCP firewall:

 1. CLASSIFY  every new TCP connection by (source, destination, port):
        ALLOW  normal application traffic (clients -> server:APP_PORT, ...)
        DENY   restricted ports, any other port on the server, clients -> logger
 2. ENFORCE   with OpenFlow rules:
        ALLOW -> per-connection forwarding flows (both directions)   prio 10
        DENY  -> short-lived drop flow for (src, dst, dport)         prio 500
        BLOCK -> drop *all* IP traffic from the source, hard timeout prio 1000
 3. ADAPT     (dynamic mode only)
        * a source that opens >= SYN_THRESHOLD connections within SYN_WINDOW_S
          (connection flood / scan) is BLOCKED
        * a source that is DENIED DENY_ESCALATE_COUNT times within
          DENY_ESCALATE_WINDOW_S (repeated unauthorised access) is BLOCKED
        * the block flow carries hard_timeout=BLOCK_TIMEOUT_S and the
          SEND_FLOW_REM flag: when the switch removes it the controller gets a
          FlowRemoved event and reports UNBLOCK  -> automatic recovery
 4. REPORT    every ALLOW (sampled), DENY, BLOCK and UNBLOCK is sent as a JSON line
        over a TCP socket to the centralised logger (see README_part1.md).
        Alerts are queued and sent by a background green thread, so a slow
        logger never delays packet-in handling.

Modes (environment variable FW_MODE):
    dynamic  (default)  everything above
    static              only the static classification (DENY rules); no rate
                        based blocking  -> the baseline for the evaluation
    none                plain learning switch, no firewall at all

Tunables: FW_SYN_THRESHOLD, FW_SYN_WINDOW_S, FW_BLOCK_TIMEOUT_S,
          FW_DENY_ESCALATE_COUNT, FW_DENY_ESCALATE_WINDOW_S, ... (see config.py)

Run:  ryu-manager firewall_controller.py
"""
import json
import os
import socket
import sys
import time
from collections import deque

try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
except NameError:
    pass
import config

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

# flow priorities and cookie
PRIO_MISS, PRIO_ALLOW_IP, PRIO_ALLOW_TCP, PRIO_DENY, PRIO_BLOCK = 0, 5, 10, 500, 1000
BLOCK_COOKIE = 0xB10C


def _env(name, default):
    raw = os.environ.get("FW_" + name)
    if raw is None:
        return default
    return type(default)(raw)


def classify(src, dst, dport, cfg=config):
    """Static policy. Returns ('ALLOW'|'DENY', reason)."""
    if dport in cfg.RESTRICTED_PORTS:
        return "DENY", f"restricted port {dport}"
    if dst == cfg.SERVER_IP and dport != cfg.APP_PORT:
        return "DENY", f"port {dport} not exposed by server"
    if dst == cfg.LOGGER_IP and src != cfg.ROOT_NS_IP:
        return "DENY", "logger accepts reports from the controller only"
    return "ALLOW", "permitted by policy"


class SDNFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = os.environ.get("FW_MODE", "dynamic").lower()
        if self.mode not in ("dynamic", "static", "none"):
            raise ValueError("FW_MODE must be dynamic, static or none")
        c = config
        self.syn_threshold = _env("SYN_THRESHOLD", c.SYN_THRESHOLD)
        self.syn_window = _env("SYN_WINDOW_S", float(c.SYN_WINDOW_S))
        self.block_timeout = _env("BLOCK_TIMEOUT_S", int(c.BLOCK_TIMEOUT_S))
        self.deny_count = _env("DENY_ESCALATE_COUNT", c.DENY_ESCALATE_COUNT)
        self.deny_window = _env("DENY_ESCALATE_WINDOW_S", float(c.DENY_ESCALATE_WINDOW_S))
        self.deny_flow_timeout = _env("DENY_FLOW_TIMEOUT_S", int(c.DENY_FLOW_TIMEOUT_S))
        self.idle_timeout = _env("FLOW_IDLE_TIMEOUT_S", int(c.FLOW_IDLE_TIMEOUT_S))
        self.allow_log_interval = _env("ALLOW_LOG_INTERVAL_S", float(c.ALLOW_LOG_INTERVAL_S))

        self.exempt = {c.SERVER_IP, c.LOGGER_IP, c.ROOT_NS_IP}   # never blocked
        self.mac_to_port = {}       # dpid -> {mac: port}
        self.syn_hist = {}          # src_ip -> deque[timestamps of new connections]
        self.deny_hist = {}         # src_ip -> deque[timestamps of denials]
        self.blocked = {}           # src_ip -> time the block was installed
        self.allow_logged = {}      # (src,dst,dport) -> last time an ALLOW was logged
        self.stats = {"packet_in": 0, "allow": 0, "deny": 0, "block": 0,
                      "unblock": 0, "alerts_sent": 0, "alerts_failed": 0}

        self._alerts = hub.Queue(1000)
        hub.spawn(self._alert_worker)
        self.logger.info("SDNFirewall started: mode=%s syn_threshold=%s/%ss block_timeout=%ss",
                         self.mode, self.syn_threshold, self.syn_window, self.block_timeout)

    # ------------------------------------------------------------------
    # alert path: controller -> logger over TCP (low-level sockets)
    # ------------------------------------------------------------------
    def _alert(self, event, ts=None, **fields):
        rec = {"event": event, "ts": ts if ts is not None else time.time()}
        rec.update({k: v for k, v in fields.items() if v is not None})
        try:
            self._alerts.put_nowait(rec)
        except Exception:                      # queue full: drop, never block
            self.stats["alerts_failed"] += 1

    def _alert_worker(self):
        sock = None
        while True:
            rec = self._alerts.get()
            line = (json.dumps(rec) + "\n").encode()
            sent = False
            for _ in range(2):                 # one reconnect attempt
                try:
                    if sock is None:
                        sock = socket.create_connection(
                            (config.LOGGER_IP, config.LOGGER_PORT), timeout=2)
                        sock.settimeout(2)
                    sock.sendall(line)
                    if not sock.recv(4096):
                        raise OSError("logger closed the connection")
                    sent = True
                    break
                except OSError as exc:
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
                    sock = None
                    last = exc
            if sent:
                self.stats["alerts_sent"] += 1
            else:
                self.stats["alerts_failed"] += 1
                self.logger.error("could not reach logger %s:%s: %s",
                                  config.LOGGER_IP, config.LOGGER_PORT, last)

    # ------------------------------------------------------------------
    # OpenFlow helpers
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, PRIO_MISS, parser.OFPMatch(), actions)
        self.logger.info("switch %s connected, table-miss installed", dp.id)
        self._alert("INFO", reason=f"switch {dp.id} connected (mode={self.mode})")

    def add_flow(self, dp, priority, match, actions, idle=0, hard=0, cookie=0, flags=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)] if actions else []
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle,
                                      hard_timeout=hard, cookie=cookie, flags=flags))

    def _packet_out(self, dp, msg, in_port, out_port):
        parser = dp.ofproto_parser
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER, in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)], data=msg.data))

    # ------------------------------------------------------------------
    # packet-in
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        self.stats["packet_in"] += 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return
        table = self.mac_to_port.setdefault(dp.id, {})
        table[eth.src] = in_port

        ip = pkt.get_protocol(ipv4.ipv4)
        if ip is None:                                   # ARP etc.: plain L2 forwarding
            self._l2_forward(dp, msg, in_port, table.get(eth.dst))
            return
        t = pkt.get_protocol(tcp.tcp)
        if t is None:                                    # ICMP / UDP: allowed, not inspected
            self._handle_other_ip(dp, msg, in_port, eth, ip, table)
            return
        self._handle_tcp(dp, msg, in_port, eth, ip, t, table)

    def _l2_forward(self, dp, msg, in_port, out_port):
        self._packet_out(dp, msg, in_port, out_port or dp.ofproto.OFPP_FLOOD)

    def _handle_other_ip(self, dp, msg, in_port, eth, ip, table):
        parser = dp.ofproto_parser
        out_port = table.get(eth.dst)
        if out_port is None:
            self._l2_forward(dp, msg, in_port, None)
            return
        match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=ip.proto, ipv4_src=ip.src, ipv4_dst=ip.dst)
        self.add_flow(dp, PRIO_ALLOW_IP, match, [parser.OFPActionOutput(out_port)],
                      idle=self.idle_timeout)
        self._packet_out(dp, msg, in_port, out_port)

    def _handle_tcp(self, dp, msg, in_port, eth, ip, t, table):
        src, dst, dport = ip.src, ip.dst, t.dst_port
        now = time.time()
        syn = bool(t.bits & tcp.TCP_SYN) and not (t.bits & tcp.TCP_ACK)

        if self.mode != "none":
            if src in self.blocked and src not in self.exempt:
                return                                   # late packet-in from a blocked host
            verdict, why = classify(src, dst, dport)
            if verdict == "DENY":
                self._deny(dp, src, dst, dport, why, now)
                return
            if self.mode == "dynamic" and syn and src not in self.exempt:
                first = self._record(self.syn_hist, src, now, self.syn_window)
                if len(self.syn_hist[src]) >= self.syn_threshold:
                    self._block(dp, src, dst, dport,
                                f"rate limit exceeded: {len(self.syn_hist[src])} new "
                                f"connections in {self.syn_window:g}s", first)
                    return
            if syn:
                self._log_allow(src, dst, dport, why, now)
        self._install_tcp_path(dp, msg, in_port, eth, ip, t, table)

    # ---- allow ---------------------------------------------------------
    def _install_tcp_path(self, dp, msg, in_port, eth, ip, t, table):
        parser = dp.ofproto_parser
        out_port = table.get(eth.dst)
        if out_port is None:                             # destination unknown yet: flood once
            self._l2_forward(dp, msg, in_port, None)
            return
        ipt = dict(eth_type=ether_types.ETH_TYPE_IP, ip_proto=6)
        fwd = parser.OFPMatch(in_port=in_port, ipv4_src=ip.src, ipv4_dst=ip.dst,
                              tcp_src=t.src_port, tcp_dst=t.dst_port, **ipt)
        rev = parser.OFPMatch(in_port=out_port, ipv4_src=ip.dst, ipv4_dst=ip.src,
                              tcp_src=t.dst_port, tcp_dst=t.src_port, **ipt)
        self.add_flow(dp, PRIO_ALLOW_TCP, fwd, [parser.OFPActionOutput(out_port)],
                      idle=self.idle_timeout)
        self.add_flow(dp, PRIO_ALLOW_TCP, rev, [parser.OFPActionOutput(in_port)],
                      idle=self.idle_timeout)
        self._packet_out(dp, msg, in_port, out_port)

    def _log_allow(self, src, dst, dport, why, now):
        key = (src, dst, dport)
        if now - self.allow_logged.get(key, 0) < self.allow_log_interval:
            return
        self.allow_logged[key] = now
        self.stats["allow"] += 1
        self._alert("ALLOW", ts=now, src_ip=src, dst_ip=dst, dst_port=dport,
                    proto="TCP", reason=why)

    # ---- deny ----------------------------------------------------------
    def _deny(self, dp, src, dst, dport, why, now):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=6,
                                ipv4_src=src, ipv4_dst=dst, tcp_dst=dport)
        self.add_flow(dp, PRIO_DENY, match, [], hard=self.deny_flow_timeout)
        self.stats["deny"] += 1
        self._alert("DENY", ts=now, src_ip=src, dst_ip=dst, dst_port=dport,
                    proto="TCP", reason=why)
        if self.mode == "dynamic" and src not in self.exempt:
            first = self._record(self.deny_hist, src, now, self.deny_window)
            if len(self.deny_hist[src]) >= self.deny_count:
                self._block(dp, src, dst, dport,
                            f"repeated unauthorised access: {len(self.deny_hist[src])} "
                            f"denials in {self.deny_window:g}s", first)

    # ---- block / unblock -----------------------------------------------
    def _record(self, hist, src, now, window):
        """Append `now` to the sliding window of `src`; return the oldest timestamp kept."""
        dq = hist.setdefault(src, deque())
        dq.append(now)
        while dq and now - dq[0] > window:
            dq.popleft()
        return dq[0]

    def _block(self, dp, src, dst, dport, reason, first_seen):
        if src in self.blocked:
            return
        parser = dp.ofproto_parser
        now = time.time()
        self.blocked[src] = now
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src)
        self.add_flow(dp, PRIO_BLOCK, match, [], hard=self.block_timeout,
                      cookie=BLOCK_COOKIE, flags=dp.ofproto.OFPFF_SEND_FLOW_REM)
        self.syn_hist.pop(src, None)
        self.deny_hist.pop(src, None)
        self.stats["block"] += 1
        self.logger.warning("BLOCK %s for %ss: %s", src, self.block_timeout, reason)
        self._alert("BLOCK", ts=now, first_seen_ts=first_seen, src_ip=src, dst_ip=dst,
                    dst_port=dport, proto="TCP", reason=reason, timeout=self.block_timeout)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed(self, ev):
        msg = ev.msg
        if msg.cookie != BLOCK_COOKIE:
            return
        src = msg.match.get("ipv4_src") if hasattr(msg.match, "get") else msg.match["ipv4_src"]
        started = self.blocked.pop(src, None)
        if msg.reason != msg.datapath.ofproto.OFPRR_HARD_TIMEOUT:
            return                                       # removed by an operator, not expiry
        self.stats["unblock"] += 1
        self.logger.warning("UNBLOCK %s (block timeout expired)", src)
        self._alert("UNBLOCK", src_ip=src, reason="block timeout expired",
                    blocked_for_s=round(time.time() - started, 3) if started else None)
