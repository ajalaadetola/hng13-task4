#!/usr/bin/env python3
from datetime import datetime
import re
import subprocess
import argparse
import sys
import ipaddress
import json
import os
import sys

CONFIG_FILE = "/tmp/vpcctl_config.json"

def run(cmd):
    """Run a shell command safely"""
    print(f"> {cmd}")
    # subprocess.run(cmd, shell=True, check=True)
    subprocess.run(cmd.split(), check=True)

def load_config():
    """Load JSON config from /tmp, or create a new one."""
    if not os.path.exists(CONFIG_FILE):
        return {"networks": {}, "namespaces": {}, "peering": {}, "acls": {} }
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


def save_config(cfg):
    """Save the JSON config to /tmp."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)

# ---------- CREATE COMMANDS ----------
def create_bridge(name, ip=None):
    cfg = load_config()
    if name in cfg["networks"]:
        print(f"⚠️ Bridge with {name} already exists in config.")
        return
    if ip:
        run(f"ip link add name {name} type bridge")
        run(f"ip addr add {ip} dev {name}")
        run(f"ip link set {name} up")
        run(f"echo 1 > /proc/sys/net/ipv4/conf/{name}/forwarding")

        cfg["networks"][name] = {
            "cidr": ip,
            "created_at": datetime.now().isoformat()
            }
        save_config(cfg)
        print(f"✅ Bridge {name} created with IP {ip}.")
    else:
        run(f"ip link add name {name} type bridge")
        cfg["networks"][name] = {"cidr": ""}
        save_config(cfg)
        print(f"✅ Bridge {name} created without IP.")
    


def check_subnet(subnet_cidr,vpc_cidr):
    try:
        subnet = ipaddress.ip_network(subnet_cidr,strict=False)
        vnet = ipaddress.ip_network(vpc_cidr,strict=False)

        return subnet.subnet_of(vnet)
    except ValueError as e:
        print(f"❌ Invalid CIDR notation: {e}")
        return False
    
def get_network_addr(ip_cidr):
    try:
        network = ipaddress.ip_network(ip_cidr,strict=False)
        network_ip = str(network.network_address)
        cidr_prefix = str(network.prefixlen)

        return f"{network_ip}/{cidr_prefix}"
    except ValueError as e:
        print(f"Error: Invalid IP/CIDR format. {e}")
        return None

def create_namespace(name, ip=None, bridge=None):
    cfg = load_config()

    if name in cfg["namespaces"]:
        print(f"⚠️ Namespace {name} already exists in config.")
        return

    if bridge not in cfg["networks"]:
        print(f"❌ Bridge {bridge} not found in config. Create it first.")
        sys.exit(1)
    
    bridge_cidr = cfg["networks"][bridge]["cidr"]
    if ip and bridge_cidr:
        if not check_subnet(ip, bridge_cidr):
            print(f"❌ IP {ip} is not in the subnet of bridge {bridge} ({bridge_cidr}).")
            sys.exit(1)
    

    if ip and bridge:
        # Auto-create veth and assign IP
        veth_ns = f"{name}_ns"
        veth_host = f"{name}_br"
        run(f"ip netns add {name}")
        run(f"ip link add {veth_ns} type veth peer name {veth_host}")
        # run(f"ip link set {veth_ns} netns {name}")
        run(f"ip link set {veth_host} master {bridge}")
        run(f"ip link set {veth_host} up")

        run(f"ip link set {veth_ns} netns {name}")
        run(f"ip netns exec {name} ip link set lo up")
        run(f"ip netns exec {name} ip link set {veth_ns} up")
        run(f"ip netns exec {name} ip addr add {ip} dev {veth_ns}") 
        
        run(f"ip netns exec {name} ip route add default via {bridge_cidr.split('/')[0]} dev {veth_ns} onlink")


        cfg["namespaces"][name] = {
            "network_cidr": get_network_addr(ip),
            "ns_ip": ip,
            "bridge": bridge,
            "veth_ns": veth_ns,
            "veth_host": veth_host,
            "public": False,
            "created_at": datetime.now().isoformat()
        }
        save_config(cfg)

        print(f"✅ Veth {veth_ns} <-> {veth_host} created and IP {ip} assigned.")
    else:
        run(f"ip netns add {name}")
        cfg["namespaces"][name] = {
            "ip": "",
            "bridge": ""
        }
        save_config(cfg)
        print(f"⚠️  Namespace {name} created Without IP. No IP or bridge provided")

def create_veth(name_ns, name_host, namespace, bridge):
    run(f"ip link add {name_ns} type veth peer name {name_host}")
    run(f"ip link set {name_ns} netns {namespace}")
    run(f"ip link set {name_host} master {bridge}")
    run(f"ip link set {name_host} up")
    run(f"ip netns exec {namespace} ip link set {name_ns} up")
    print(f"✅ Veth {name_ns} <-> {name_host} created and attached to {namespace} & {bridge}.")



# ---------- SET COMMANDS ----------
def set_ip(namespace, interface, ip):
    run(f"ip netns exec {namespace} ip addr add {ip} dev {interface}")
    run(f"ip netns exec {namespace} ip link set {interface} up")
    print(f"✅ IP {ip} assigned to {interface} in {namespace}.")

# def set_route(namespace, destination, via):
#     run(f"ip netns exec {namespace} ip route add {destination} via {via}")
#     print(f"✅ Route {destination} via {via} set in {namespace}.")

def set_route(ns1, ns2, bridge):
    cfg = load_config()
    if bridge not in cfg["networks"]:
        print(f"⚠️ Bridge with {bridge} does not exist in config.")
        return


    if ns1 not in cfg["namespaces"]:
        print(f"⚠️ Namespace {ns1} does not  exist in config.")
        return
    if ns2 not in cfg["namespaces"]:
        print(f"⚠️ Namespace {ns2} does not  exist in config.")
        return
    ns1_network_ip = cfg["namespaces"][ns1]["network_cidr"]
    ns2_network_ip = cfg["namespaces"][ns2]["network_cidr"]
    bridge_cidr = cfg["networks"][bridge]["cidr"]

    run(f"ip netns exec {ns1} ip route add {ns2_network_ip} via {bridge_cidr.split('/')[0]}")
    run(f"ip netns exec {ns2} ip route add {ns1_network_ip} via {bridge_cidr.split('/')[0]}")

    print(f"✅ Route updated for {ns1} and {ns2}.")


def enable_nat(namespace, ext_if=None):
    if ext_if:
        print(f"🌐 Using specified external interface: {ext_if}")
    else:
        # ------------DETECT EXTERNAL INTERFACE-------------
        route_output = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True
            ).stdout

        match = re.search(r'dev (\w+)', route_output)
        ext_if = match.group(1) if match else None

        # ext_if = run(f"ip route show default | grep -oP 'dev \K\w+'").stdout.decode().strip()
        if not ext_if:
            print("External Interface could not be detected. Please specify it manually.")
            return
        print(f"🌐 Detected external interface: {ext_if}")



    cfg = load_config()
    if namespace not in cfg["namespaces"]:
        print(f"⚠️ Namespace {namespace} does not  exist in config.")
        return
    ns_cidr = cfg["namespaces"][namespace]["ns_ip"]
    bridge = cfg["namespaces"][namespace]["bridge"]
    bridge_cidr = cfg["networks"][bridge]["cidr"]

    if not ns_cidr or not bridge_cidr:
        print(f"❌ Namespace {namespace} or Bridge {bridge} does not have an IP assigned.")
        return

    run("sysctl -w net.ipv4.ip_forward=1")
    run("iptables -t nat -F POSTROUTING")
    run(f"iptables -t nat -A POSTROUTING -s {ns_cidr} -o {ext_if} -j MASQUERADE")
    run(f"iptables -A FORWARD -i {bridge} -o {ext_if} -s {ns_cidr} -j ACCEPT")
    run(f"iptables -A FORWARD -i {ext_if} -o {bridge} -d {ns_cidr} -m state --state ESTABLISHED,RELATED -j ACCEPT")

    cfg["namespaces"][namespace]["public"] = True
    save_config(cfg)
    print(f"✅ NAT enabled for {namespace} with IP {ns_cidr} via {ext_if}.")

# ---------- DELETE COMMANDS ----------
def delete_bridge(name):
    run(f"ip link set {name} down || true")
    run(f"ip link delete {name} type bridge || true")
    print(f"✅ Bridge {name} deleted.")

def delete_namespace(name):
    run(f"ip netns del {name} || true")
    print(f"✅ Namespace {name} deleted.")

def delete_veth(name):
    run(f"ip link del {name} || true")
    print(f"✅ Veth {name} deleted.")

# ---------- STATUS ----------
def status():
    print("\n=== Bridges ===")
    run("ip link show type bridge || true")
    print("\n=== Namespaces ===")
    run("ip netns list")
    print("\n=== IPs and Routes ===")
    run("ip addr")
    run("ip route")

def show_config():
    cfg = load_config()
    print(json.dumps(cfg, indent=4))

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="vPCCTL - Modular VPC CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # CREATE
    parser_create = subparsers.add_parser("create", help="Create resources")
    parser_create.add_argument("type", choices=["bridge", "namespace", "veth"])
    parser_create.add_argument("name", help="Resource name")
    parser_create.add_argument("--ip", help="IP address for bridge or namespace (with CIDR)")
    parser_create.add_argument("--veth-host", help="Host-side veth name (for namespace auto veth creation)")
    parser_create.add_argument("--bridge", help="Bridge name (for namespace auto veth creation)")

    # SET
    parser_set = subparsers.add_parser("set", help="Set IP, route, NAT")
    parser_set.add_argument("type", choices=["ip", "route", "nat"])
    parser_set.add_argument("args", nargs="*")

    # DELETE
    parser_delete = subparsers.add_parser("delete", help="Delete resources")
    parser_delete.add_argument("type", choices=["bridge", "namespace", "veth"])
    parser_delete.add_argument("name")

    # STATUS
    subparsers.add_parser("status", help="Show vPC status")

     # CONFIG
    subparsers.add_parser("config", help="Show vPC configuration")

    args = parser.parse_args()

    if args.command == "create":
        if args.type == "bridge":
            create_bridge(args.name, args.ip)
        elif args.type == "namespace":
            create_namespace(args.name, ip=args.ip, bridge=args.bridge)
        elif args.type == "veth":
            print("Usage: vpcctl create veth <veth_ns> <veth_host> <namespace> <bridge>")
            # Example: vpcctl create veth v-sub-1 v-sub-1_br sub_1 v-net-1

    elif args.command == "set":
        if args.type == "ip":
            set_ip(*args.args)
        elif args.type == "route":
            set_route(*args.args)
        elif args.type == "nat":
            enable_nat(*args.args)

    elif args.command == "delete":
        if args.type == "bridge":
            delete_bridge(args.name)
        elif args.type == "namespace":
            delete_namespace(args.name)
        elif args.type == "veth":
            delete_veth(args.name)

    elif args.command == "status":
        status()
    
    elif args.command == "config":
        show_config()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
