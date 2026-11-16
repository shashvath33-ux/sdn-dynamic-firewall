#!/usr/bin/env python3
"""
Mininet topology for the Dynamic Firewall + Security Event Logger  (Part 1)

                         +---------+        OpenFlow        +------------------+
   h1 10.0.0.1  ---------|         |<---------------------->| Ryu / POX        |
   h2 10.0.0.2  ---------|         |   (127.0.0.1:6653)     | firewall (Part 3)|
   h3 10.0.0.3  (attacker)|   s1    |                        +--------+---------+
   h4 10.0.0.4  ---------|  (OVS)  |                                 |
   srv    10.0.0.10 -----|         |      alerts over TCP 9999       |
   logger 10.0.0.100 ----|         |<--------------------------------+
   root-ns 10.0.0.254 ---|         |   (controller lives in the root namespace,
                         +---------+    reaches the logger via this extra port)

Usage (must be root):
    sudo python3 topology.py                       # build, start logger, open CLI
    sudo python3 topology.py --delay 10ms --loss 2 # emulate a worse network
    sudo python3 topology.py --bw 10               # 10 Mbit/s host links (congestion tests)
    sudo python3 topology.py --test                # automated sanity check, no CLI
    sudo python3 topology.py --controller-port 6633 --of-version OpenFlow10   # POX
"""
import argparse
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from functools import partial

from mininet.cli import CLI
from mininet.link import Link, TCLink
from mininet.log import info, setLogLevel, error
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, RemoteController

import config

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_args():
    p = argparse.ArgumentParser(description="Custom Mininet topology for the SDN firewall project")
    p.add_argument("--controller-ip", default=config.CONTROLLER_IP)
    p.add_argument("--controller-port", type=int, default=config.CONTROLLER_PORT)
    p.add_argument("--of-version", default=config.OF_VERSION,
                   help="OpenFlow version for s1 (OpenFlow13 for Ryu, OpenFlow10 for POX)")
    p.add_argument("--datapath", choices=["kernel", "user"], default="kernel",
                   help="OVS datapath. Use 'user' if the openvswitch kernel module is missing "
                        "(e.g. WSL2 / minimal kernels); slower but functionally the same")
    p.add_argument("--bw", type=float, help="host link bandwidth in Mbit/s")
    p.add_argument("--delay", help="host link one-way delay, e.g. 5ms")
    p.add_argument("--loss", type=float, help="host link packet loss in percent")
    p.add_argument("--no-logger", action="store_true",
                   help="do not auto-start logger_server.py on the logger host")
    p.add_argument("--no-alert-flows", action="store_true",
                   help="do not pre-install the controller->logger alert-path flows")
    p.add_argument("--log-dir", default=os.path.join(HERE, config.LOG_DIR))
    p.add_argument("--test", action="store_true", help="run self-test and exit (no CLI)")
    p.add_argument("--no-cli", action="store_true", help="keep running without the CLI (Ctrl-C to stop)")
    return p.parse_args()


def controller_reachable(ip, port):
    try:
        socket.create_connection((ip, port), timeout=1).close()
        return True
    except OSError:
        return False


def build_network(args):
    """Create (but do not start) the network. Returns (net, root, s1)."""
    net = Mininet(controller=None, link=TCLink, autoSetMacs=False, build=False)
    net.addController("c0", controller=RemoteController,
                      ip=args.controller_ip, port=args.controller_port)

    # fail_mode=secure: if the controller is down the switch forwards nothing,
    # which is what a firewall should do (no controller = no implicit allow).
    s1 = net.addSwitch("s1", cls=OVSSwitch, protocols=args.of_version,
                       failMode="secure", dpid="0000000000000001",
                       datapath=getattr(args, "datapath", "kernel"))

    link_opts = {}
    if args.bw is not None:
        link_opts["bw"] = args.bw
    if args.delay:
        link_opts["delay"] = args.delay
    if args.loss is not None:
        link_opts["loss"] = args.loss

    prefix = f"/{config.PREFIX_LEN}"
    for name, h in config.CLIENTS.items():
        net.addHost(name, ip=h["ip"] + prefix, mac=h["mac"])
    net.addHost(config.SERVER_NAME, ip=config.SERVER_IP + prefix, mac=config.SERVER_MAC)
    net.addHost(config.LOGGER_NAME, ip=config.LOGGER_IP + prefix, mac=config.LOGGER_MAC)

    for name in list(config.CLIENTS) + [config.SERVER_NAME, config.LOGGER_NAME]:
        net.addLink(name, s1, **link_opts)

    # Plug the root namespace into the switch so the controller process can
    # talk to the logger host (see diagram above). No shaping on this link.
    root = Node("root", inNamespace=False)
    root_intf = net.addLink(root, s1, cls=Link).intf1
    root.setIP(config.ROOT_NS_IP + prefix, intf=root_intf)
    return net, root, s1


def disable_offload(net, *extra_nodes):
    """Needed with --datapath user: the userspace switch does not fix up TCP/UDP
    checksums that the veth drivers left to 'offload', so hosts would drop TCP."""
    for node in list(net.hosts) + list(net.switches) + list(extra_nodes):
        for intf in node.intfNames():
            node.cmd(f"ethtool -K {intf} tx off rx off gro off gso off tso off 2>/dev/null")


def install_alert_path_flows(s1, of_version):
    """
    Pre-install high-priority flows so controller->logger alert traffic and
    its ARP always work, even if the firewall rules are strict or the
    controller wipes the table. Priority 65000 is above normal firewall rules.
    Only root-ns <-> logger traffic is matched; everything else is untouched.
    """
    r, l = config.ROOT_NS_IP, config.LOGGER_IP
    flows = [
        f"priority=65000,ip,nw_src={r},nw_dst={l},actions=NORMAL",
        f"priority=65000,ip,nw_src={l},nw_dst={r},actions=NORMAL",
        f"priority=65000,arp,arp_spa={r},arp_tpa={l},actions=NORMAL",
        f"priority=65000,arp,arp_spa={l},arp_tpa={r},actions=NORMAL",
        f"priority=65000,arp,arp_tpa={r},actions=NORMAL",
        f"priority=65000,arp,arp_tpa={l},actions=NORMAL",
    ]
    for f in flows:
        s1.cmd(f'ovs-ofctl -O {of_version} add-flow s1 "{f}"')


def start_logger(net, log_dir):
    """Run logger_server.py inside the 'logger' Mininet host."""
    os.makedirs(log_dir, exist_ok=True)
    logger = net.get(config.LOGGER_NAME)
    out = open(os.path.join(log_dir, "logger_stdout.txt"), "a")
    proc = logger.popen(
        [sys.executable, os.path.join(HERE, "logger_server.py"),
         "--host", "0.0.0.0", "--port", str(config.LOGGER_PORT),
         "--log-dir", log_dir, "--quiet"],
        stdout=out, stderr=subprocess.STDOUT)
    time.sleep(1.0)
    if proc.poll() is not None:
        error("*** logger_server.py exited immediately - see logger_stdout.txt\n")
    else:
        info(f"*** Logger running on {config.LOGGER_IP}:{config.LOGGER_PORT}\n")
    return proc


def stop_logger(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)     # lets the logger print its summary
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()


def self_test(net, root, args):
    """Sanity checks that do not need the firewall controller."""
    results = []
    s1 = net.get("s1")

    results.append(("switch s1 connected to controller", bool(s1.connected())))
    out = root.cmd(f"{shlex.quote(sys.executable)} {shlex.quote(os.path.join(HERE, 'send_test_alert.py'))} "
                   f"--host {config.LOGGER_IP} --event INFO --reason self-test --ping")
    results.append(("root namespace -> logger TCP path (alert path)", "pong" in out))
    out = root.cmd(f"{shlex.quote(sys.executable)} {shlex.quote(os.path.join(HERE, 'send_test_alert.py'))} "
                   f"--host {config.LOGGER_IP} --event INFO --src 10.0.0.1 --reason self-test")
    results.append(("logger acknowledged a test event", "acked=1" in out))
    ping = net.get("h1").cmd(f"ping -c 1 -W 2 {config.SERVER_IP}")
    results.append(("h1 -> srv ping (needs the controller to allow it)", "1 received" in ping))

    print("\n=== Self-test ===")
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print("  (checks 1 and 4 need a running controller; checks 2 and 3 do not)")
    return all(ok for _, ok in results[1:3])     # logger/alert path only


def banner():
    print("\n" + "=" * 66)
    print(" Topology is up.  Hosts:")
    for n, h in config.CLIENTS.items():
        print(f"   {n:<7}{h['ip']:<12} {h['role']}")
    print(f"   {config.SERVER_NAME:<7}{config.SERVER_IP:<12} TCP server (port {config.APP_PORT})")
    print(f"   {config.LOGGER_NAME:<7}{config.LOGGER_IP:<12} security logger (port {config.LOGGER_PORT})")
    print(" Useful CLI commands:")
    print("   net | dump | pingall | h1 ping -c3 srv | xterm srv h1 h3")
    print("   sh ovs-ofctl -O OpenFlow13 dump-flows s1     (watch firewall rules)")
    print("   sh tail -f logs/security_events.log          (live security events)")
    print("=" * 66 + "\n")


def main():
    args = parse_args()
    if os.geteuid() != 0:
        sys.exit("Run with sudo:  sudo python3 topology.py")
    setLogLevel("info")

    if not controller_reachable(args.controller_ip, args.controller_port):
        print(f"WARNING: no controller listening on {args.controller_ip}:{args.controller_port}. "
              "Start Ryu first (in another terminal) or the switch will drop everything "
              "(fail_mode=secure).")

    net, root, s1 = build_network(args)
    logger_proc = None
    try:
        net.start()
        if getattr(args, "datapath", "kernel") == "user":
            disable_offload(net, root)
        if not args.no_alert_flows:
            install_alert_path_flows(s1, args.of_version)
        if not args.no_logger:
            logger_proc = start_logger(net, args.log_dir)
        time.sleep(1.5)           # give the switch time to handshake with the controller

        if args.test:
            ok = self_test(net, root, args)
            sys.exit(0 if ok else 1)
        banner()
        if args.no_cli:
            signal.pause()
        else:
            CLI(net)
    except KeyboardInterrupt:
        pass
    finally:
        stop_logger(logger_proc)
        net.stop()


if __name__ == "__main__":
    main()
