#!/usr/bin/env python3
"""
vpcctl.py - Lightweight VPC emulator on a single Linux host using network namespaces,
veth pairs, linux bridge, iptables, and routing.

Usage examples:
  sudo ./vpcctl.py create-vpc --name vpc1 --cidr 10.10.0.0/16
  sudo ./vpcctl.py add-subnet --vpc vpc1 --name public --cidr 10.10.1.0/24 --gateway 10.10.1.1 --public
  sudo ./vpcctl.py add-subnet --vpc vpc1 --name private --cidr 10.10.2.0/24 --gateway 10.10.2.1
  sudo ./vpcctl.py deploy-web --vpc vpc1 --subnet public --host-ip 10.10.1.10
  sudo ./vpcctl.py test --vpc vpc1
  sudo ./vpcctl.py peer --vpc-a vpc1 --vpc-b vpc2
  sudo ./vpcctl.py delete-vpc --name vpc1
"""

import argparse
import subprocess
import json
import os
import sys
import time
from shlex import quote

# ---------- Helpers ----------
def run(cmd, check=True, capture=False):
    print(f"+ {cmd}")
    if capture:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode != 0 and check:
            print(res.stdout, res.stderr, file=sys.stderr)
            raise SystemExit(f"Command failed: {cmd}")
        return res.stdout.strip()
    else:
        res = subprocess.run(cmd, shell=True)
        if res.returncode != 0 and check:
            raise SystemExit(f"Command failed: {cmd}")

def exists_ns(ns):
    out = run("ip netns list", capture=True)
    return ns in out.splitlines()

def ensure_sysctl(key, val="1"):
    run(f"sysctl -w {key}={val}")

# ---------- Naming helpers ----------
def br_name(vpc):
    return f"br-{vpc}"

def ns_name(vpc, subnet):
    return f"{vpc}-{subnet}"

def veth_host_name(vpc, subnet):
    name = f"v-{vpc[:3]}-{subnet[:3]}-h"
    return name[:15]  # ensure max length 15

def veth_ns_name(vpc, subnet):
    name = f"v-{vpc[:3]}-{subnet[:3]}-n"
    return name[:15]  # ensure max length 15

def gw_ip(gateway):
    return gateway  # provided

# ---------- Core functions ----------
def create_bridge(vpc):
    br = br_name(vpc)
    out = run("ip link show type bridge", capture=True)
    if br in out:
        print(f"Bridge {br} already exists (idempotent).")
        return
    run(f"ip link add name {br} type bridge")
    run(f"ip link set dev {br} up")
    print(f"Bridge {br} created and up.")

def delete_bridge(vpc):
    br = br_name(vpc)
    # remove any ip assigned
    run(f"ip link set {br} down", check=False)
    run(f"ip link del {br}", check=False)
    print(f"Deleted bridge {br} (if existed).")

def create_namespace(vpc, subnet, gateway_cidr):
    ns = ns_name(vpc, subnet)
    if exists_ns(ns):
        print(f"Namespace {ns} already exists (idempotent).")
        return
    run(f"ip netns add {ns}")
    run(f"ip netns exec {ns} ip link set lo up")
    print(f"Namespace {ns} created, loopback up.")

def delete_namespace(vpc, subnet):
    ns = ns_name(vpc, subnet)
    run(f"ip netns del {ns}", check=False)
    print(f"Deleted namespace {ns} (if existed).")

def connect_veth_to_bridge(vpc, subnet, ns_ip_cidr, br_iface=None):
    ns = ns_name(vpc, subnet)
    host_if = veth_host_name(vpc, subnet)
    ns_if = veth_ns_name(vpc, subnet)
    br = br_name(vpc)
    # idempotent: delete if exists
    run(f"ip link del {host_if}", check=False)
    # create veth pair
    run(f"ip link add {host_if} type veth peer name {ns_if}")
    # attach host side to bridge
    run(f"ip link set {host_if} master {br}")
    run(f"ip link set {host_if} up")
    # move ns side to namespace
    run(f"ip link set {ns_if} netns {ns}")
    # configure addresses
    run(f"ip netns exec {ns} ip link set {ns_if} up")
    run(f"ip netns exec {ns} ip addr add {ns_ip_cidr} dev {ns_if}")
    print(f"Connected {ns_if} -> {br} with {ns_ip_cidr}")

def add_route_for_namespace(vpc, subnet, gw):
    ns = ns_name(vpc, subnet)
    run(f"ip netns exec {ns} ip route add default via {gw}", check=False)
    print(f"Added default route in {ns} via {gw}")

def enable_ip_forwarding():
    ensure_sysctl("net.ipv4.ip_forward", "1")
    print("IP forwarding enabled on host.")

def setup_nat_for_bridge(vpc, host_iface_external):
    br = br_name(vpc)
    # NAT all outbound from bridge subnet(s) via external interface
    # Use MASQUERADE - idempotency handled by checking existing rule
    # We'll add a rule matching the bridge's address range, but simpler: match outgoing on external interface
    # Delete any existing generic masquerade rule for this external interface to avoid duplicates
    # Note: To be conservative, allow multiple VPCs: create a chain per-VPC
    chain = f"VPC_{vpc}_NAT"
    run(f"iptables -t nat -N {chain}", check=False)
    run(f"iptables -t nat -F {chain}", check=False)
    run(f"iptables -t nat -A {chain} -o {host_iface_external} -j MASQUERADE")
    # ensure POSTROUTING jumps to chain
    # remove previous jump if exists (crudely)
    run(f"iptables -t nat -C POSTROUTING -j {chain}", check=False)
    try:
        run(f"iptables -t nat -A POSTROUTING -j {chain}", check=False)
    except SystemExit:
        # likely duplicate, ignore
        pass
    print(f"NAT (MASQUERADE) set up for VPC {vpc} via {host_iface_external}.")

def remove_nat_for_vpc(vpc, host_iface_external):
    chain = f"VPC_{vpc}_NAT"
    run(f"iptables -t nat -D POSTROUTING -j {chain}", check=False)
    run(f"iptables -t nat -F {chain}", check=False)
    run(f"iptables -t nat -X {chain}", check=False)
    print(f"Removed NAT chain {chain} for VPC {vpc} (if present).")

# ---------- High-level flows ----------
def create_vpc(args):
    vpc = args.name
    cidr = args.cidr
    print(f"Creating VPC {vpc} with CIDR {cidr}")
    create_bridge(vpc)
    enable_ip_forwarding()
    print(f"VPC {vpc} created. Add subnets with add-subnet.")

def add_subnet(args):
    vpc = args.vpc
    subnet = args.name
    cidr = args.cidr
    gateway = args.gateway
    public = args.public
    if not exists_ns(ns_name(vpc, subnet)):
        create_namespace(vpc, subnet, gateway)
    create_bridge(vpc)
    # assign gateway to bridge if not already set
    br = br_name(vpc)
    # assign bridge IP for gateway (idempotent check)
    # We'll give the bridge the gateway IP (e.g., 10.10.1.1/24) so it is the router
    existing = run(f"ip -4 addr show dev {br}", capture=True)
    if gateway not in existing:
        run(f"ip addr add {gateway} dev {br}", check=False)
    run(f"ip link set {br} up", check=False)
    # connect veth and set namespace IP (we accept full host IP like 10.10.1.10/24)
    # For the namespace we expect an IP (args.host_ip) optionally; otherwise we'll use first available host IP (.10)
    ns_ip = args.host_ip if args.host_ip else None
    # decide namespace-side IP: if user passed host_ip use that; else derive .10
    if not ns_ip:
        # derive from gateway: replace last octet with 10
        parts = gateway.split(".")
        ns_ip = ".".join(parts[:3] + ["10"]) + "/" + cidr.split("/")[1]
    connect_veth_to_bridge(vpc, subnet, ns_ip)
    # add default route in namespace via gateway
    add_route_for_namespace(vpc, subnet, gateway.split("/")[0])
    # optionally setup NAT if public
    if public:
        if not args.external_iface:
            raise SystemExit("Public subnet requires --external-iface (host's internet interface) to enable NAT.")
        setup_nat_for_bridge(vpc, args.external_iface)
    print(f"Subnet {subnet} added to VPC {vpc}. public={public}")

def delete_vpc(args):
    vpc = args.name
    print(f"Deleting VPC {vpc} and cleaning up resources.")
    # list namespaces whose name startswith vpc-
    out = run("ip netns list", capture=True)
    lines = out.splitlines()
    for l in lines:
        if l.startswith(vpc + "-"):
            ns = l.split()[0]
            print(f"Deleting namespace {ns}")
            run(f"ip netns del {ns}", check=False)
    # delete veths left on host that match prefix
    # delete bridge
    # remove iptables NAT chain
    # attempt to delete veth links (pattern)
    run(f"ip -o link show | awk -F': ' '{{print $2}}' | grep '^veth-{vpc}-' | xargs -r -n1 ip link del", check=False)
    remove_nat_for_vpc(vpc, args.external_iface if args.external_iface else "eth0")
    delete_bridge(vpc)
    print("Cleanup done. Verify with `ip netns list` and `ip link show`.")

def list_vpcs(args):
    out = run("ip -o link show type bridge", capture=True)
    lines = out.splitlines()
    print("Bridges (possible VPCs):")
    for l in lines:
        print("  " + l)

# ---------- Security group / iptables from JSON ----------
def apply_policy(args):
    """
    policy JSON example:
    {
      "subnet": "10.10.1.0/24",
      "ingress": [
        {"port": 80, "protocol": "tcp", "action": "allow"},
        {"port": 22, "protocol": "tcp", "action": "deny"}
      ]
    }
    We will translate to iptables rules executed inside the namespace for that subnet.
    """
    policy_file = args.file
    with open(policy_file) as f:
        policies = json.load(f)
    # policies can be list or single
    if isinstance(policies, dict):
        policies = [policies]
    for p in policies:
        subnet = p["subnet"]
        # find namespace(s) that match this subnet -- naive: search namespaces and their IPs
        ns_list = run("ip netns list", capture=True).splitlines()
        for ns in ns_list:
            ns_name_only = ns.split()[0]
            ips = run(f"ip netns exec {ns_name_only} ip -4 addr show", capture=True)
            if subnet.split("/")[0] in ips:
                # apply rules inside ns
                print(f"Applying policy to namespace {ns_name_only}")
                # flush existing filter rules in custom chain
                chain = f"SG_{ns_name_only}"
                run(f"ip netns exec {ns_name_only} iptables -N {chain}", check=False)
                run(f"ip netns exec {ns_name_only} iptables -F {chain}", check=False)
                # default deny (if ingress defined) - but we will just add specific allow/deny entries on INPUT
                for rule in p.get("ingress", []):
                    port = rule["port"]
                    proto = rule.get("protocol", "tcp")
                    action = rule.get("action", "allow")
                    if action == "allow":
                        run(f"ip netns exec {ns_name_only} iptables -A INPUT -p {proto} --dport {port} -j ACCEPT")
                    elif action == "deny":
                        run(f"ip netns exec {ns_name_only} iptables -A INPUT -p {proto} --dport {port} -j REJECT")
                # allow established
                run(f"ip netns exec {ns_name_only} iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
                # drop by default (optional)
                run(f"ip netns exec {ns_name_only} iptables -A INPUT -j DROP")
                print(f"Policies applied in {ns_name_only}.")
    print("Policy application complete.")

# ---------- Peering ----------
def peer_vpcs(args):
    a = args.vpc_a
    b = args.vpc_b
    # create veth pair host side names
    veth_a = f"peer-{a}-{b}-a"
    veth_b = f"peer-{a}-{b}-b"
    # create pair
    run(f"ip link add {veth_a} type veth peer name {veth_b}", check=False)
    # attach each to bridges
    run(f"ip link set {veth_a} master {br_name(a)}", check=False)
    run(f"ip link set {veth_b} master {br_name(b)}", check=False)
    run(f"ip link set {veth_a} up", check=False)
    run(f"ip link set {veth_b} up", check=False)
    # Add static routes on host: to be explicit, user may add routes inside namespaces if desired
    print(f"Peering created between {a} and {b} via {veth_a}<->{veth_b}. Add routes inside namespaces as needed.")
    # Note: to restrict peering to specific CIDRs you'd add iptables rules on bridges or in namespaces

# ---------- Deploy simple web server inside a namespace ----------
def deploy_web(args):
    vpc = args.vpc
    subnet = args.subnet
    host_ip = args.host_ip
    ns = ns_name(vpc, subnet)
    if not exists_ns(ns):
        raise SystemExit(f"Namespace {ns} not found. Create subnet first.")
    # install or rely on python3 -m http.server
    # launch server with nohup inside namespace on port 80 (requires root inside ns)
    logfile = f"/tmp/{ns}-web.log"
    # kill existing server on port 80 (if any) inside namespace
    run(f"ip netns exec {ns} bash -c \"fuser -k 80/tcp || true\"", check=False)
    cmd = f"ip netns exec {ns} nohup python3 -m http.server 80 >/tmp/{ns}-web.log 2>&1 &"
    run(cmd)
    print(f"Deployed python http.server in {ns} on 0.0.0.0:80 (namespace internal). Log: {logfile}")

# ---------- Testing helpers ----------
def tests(args):
    vpc = args.vpc
    # basic tests: list namespaces, ping between subnets, curl from host to public webserver
    br = br_name(vpc)
    print("Namespaces:")
    print(run("ip netns list", capture=True))
    # find subnets for this vpc
    out = run("ip netns list", capture=True)
    ns_names = [l.split()[0] for l in out.splitlines() if l.startswith(vpc + "-")]
    print("Namespaces for VPC:", ns_names)
    for ns in ns_names:
        print(f"-- IPs in {ns}:")
        print(run(f"ip netns exec {ns} ip -4 addr show", capture=True))
    # ping test: pick first two ns and ping
    if len(ns_names) >= 2:
        a = ns_names[0]; b = ns_names[1]
        # get IP of b
        outb = run(f"ip netns exec {b} ip -4 addr show | awk '/inet /{{print $2}}' | head -n1", capture=True)
        if outb:
            ipb = outb.split("/")[0]
            print(f"Pinging from {a} -> {ipb}")
            run(f"ip netns exec {a} ping -c 3 {ipb}")
    print("Tests completed. For NAT test, try curl from namespace to external IP (e.g., 8.8.8.8)")

# ---------- CLI argument parser ----------
def build_parser():
    p = argparse.ArgumentParser(prog="vpcctl", description="Mini VPC on Linux using namespaces and bridges.")
    sub = p.add_subparsers(dest="cmd")

    # create-vpc
    c = sub.add_parser("create-vpc")
    c.add_argument("--name", required=True)
    c.add_argument("--cidr", required=True)

    # add-subnet
    s = sub.add_parser("add-subnet")
    s.add_argument("--vpc", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--cidr", required=True, help="e.g. 10.10.1.0/24")
    s.add_argument("--gateway", required=True, help="gateway ip for bridge e.g. 10.10.1.1/24")
    s.add_argument("--public", action="store_true", help="mark subnet as public (enables NAT)")
    s.add_argument("--external-iface", help="host's external interface (required for public nat)")
    s.add_argument("--host-ip", help="ip to assign to namespace veth (e.g. 10.10.1.10/24)")

    # delete-vpc
    d = sub.add_parser("delete-vpc")
    d.add_argument("--name", required=True)
    d.add_argument("--external-iface", help="host external interface (for NAT cleanup)")

    # list-vpcs
    sub.add_parser("list-vpcs")

    # apply policy
    ap = sub.add_parser("apply-policy")
    ap.add_argument("--file", required=True)

    # peer
    pr = sub.add_parser("peer")
    pr.add_argument("--vpc-a", required=True)
    pr.add_argument("--vpc-b", required=True)

    # deploy web
    dw = sub.add_parser("deploy-web")
    dw.add_argument("--vpc", required=True)
    dw.add_argument("--subnet", required=True)
    dw.add_argument("--host-ip", required=False)

    # tests
    t = sub.add_parser("test")
    t.add_argument("--vpc", required=True)

    return p

def main():
    if os.geteuid() != 0:
        print("This tool must be run as root. Use sudo.")
        sys.exit(1)
    parser = build_parser()
    args = parser.parse_args()
    if not args.cmd:
        parser.print_help(); sys.exit(0)
    if args.cmd == "create-vpc":
        create_vpc(args)
    elif args.cmd == "add-subnet":
        add_subnet(args)
    elif args.cmd == "delete-vpc":
        delete_vpc(args)
    elif args.cmd == "list-vpcs":
        list_vpcs(args)
    elif args.cmd == "apply-policy":
        apply_policy(args)
    elif args.cmd == "peer":
        peer_vpcs(args)
    elif args.cmd == "deploy-web":
        deploy_web(args)
    elif args.cmd == "test":
        tests(args)
    else:
        print("Unknown command:", args.cmd)

if __name__ == "__main__":
    main()
