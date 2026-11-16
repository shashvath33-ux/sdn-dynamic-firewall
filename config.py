"""
Shared configuration for the Dynamic Firewall + Security Event Logger project.

Owned by Part 1. Parts 2 and 3 can simply `import config` (or copy the values)
so that the topology, the TCP apps and the Ryu controller all agree on the
same IP addresses and ports.
"""

# ----------------------------- Addressing ---------------------------------
SUBNET_CIDR = "10.0.0.0/24"
PREFIX_LEN = 24

# Clients. h3 is the "attacker" we use for rapid / unauthorised traffic,
# h4 is a second ordinary client used for the multi-client tests.
CLIENTS = {
    "h1": {"ip": "10.0.0.1", "mac": "00:00:00:00:00:01", "role": "normal client"},
    "h2": {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "role": "normal client"},
    "h3": {"ip": "10.0.0.3", "mac": "00:00:00:00:00:03", "role": "attacker (rapid/unauthorised)"},
    "h4": {"ip": "10.0.0.4", "mac": "00:00:00:00:00:04", "role": "normal client"},
}

SERVER_NAME = "srv"
SERVER_IP = "10.0.0.10"
SERVER_MAC = "00:00:00:00:00:10"

LOGGER_NAME = "logger"
LOGGER_IP = "10.0.0.100"
LOGGER_MAC = "00:00:00:00:01:00"

# The Ryu/POX controller runs in the machine's root namespace, not inside a
# Mininet host. To let it open a TCP connection to the logger host, the
# topology plugs the root namespace into the switch with this address.
ROOT_NS_IP = "10.0.0.254"

# ------------------------------- Ports ------------------------------------
APP_PORT = 5000          # the normal TCP application server (Part 2)
RESTRICTED_PORT = 6000   # a port the firewall policy should deny (Part 3)
LOGGER_PORT = 9999       # centralised security-event logger (Part 1)

# --------------------------- OpenFlow controller --------------------------
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653   # Ryu default (POX default is 6633)
OF_VERSION = "OpenFlow13"  # Ryu: OpenFlow13. POX only speaks OpenFlow10.

# ------------------------------- Logging ----------------------------------
LOG_DIR = "logs"
TEXT_LOG = "security_events.log"
JSONL_LOG = "security_events.jsonl"

# =========================================================================
# Added for Parts 2 and 3 (TCP application + firewall policy)
# Every value in the "Firewall policy" block can be overridden at run time
# with an environment variable of the form FW_<NAME>, e.g.
#     FW_SYN_THRESHOLD=20 FW_BLOCK_TIMEOUT_S=60 ryu-manager firewall_controller.py
# =========================================================================

# ------------------------- TCP application (Part 2) -----------------------
SERVER_MAX_CLIENTS = 20        # concurrent connections the app server serves
SERVER_IDLE_TIMEOUT_S = 6      # server reaps a silent connection after this long

# --------------------------- Firewall policy (Part 3) ---------------------
# Traffic classification, evaluated per new TCP connection (src, dst, dport):
#   dport in RESTRICTED_PORTS                        -> DENY   (static rule)
#   dst == server and dport != APP_PORT              -> DENY   (default-deny to the server)
#   dst == logger  and src not the controller        -> DENY   (only the controller may report)
#   dst == server and dport == APP_PORT              -> ALLOW  (but rate-limited, see below)
#   anything else                                    -> ALLOW
# Dynamic rule: a source that opens >= SYN_THRESHOLD new connections within
# SYN_WINDOW_S seconds, or that is denied >= DENY_ESCALATE_COUNT times within
# DENY_ESCALATE_WINDOW_S seconds, is BLOCKED for BLOCK_TIMEOUT_S seconds. The
# block is a hard-timeout flow, so the switch removes it itself and the
# controller reports UNBLOCK (automatic recovery).
RESTRICTED_PORTS = [RESTRICTED_PORT]
SYN_THRESHOLD = 10
SYN_WINDOW_S = 3.0
BLOCK_TIMEOUT_S = 30
DENY_ESCALATE_COUNT = 3
DENY_ESCALATE_WINDOW_S = 30.0
DENY_FLOW_TIMEOUT_S = 1        # drop flow lifetime; bounds how often a DENY is logged (1 per s per flow)
FLOW_IDLE_TIMEOUT_S = 10       # idle timeout of allowed per-connection flows
ALLOW_LOG_INTERVAL_S = 30.0    # log an ALLOW for a given (src,dst,dport) at most this often
