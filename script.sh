#!/usr/bin/env bash
set -e  # stop on first error

# ------------- CONFIGURATION -------------
VPC_NAME="v-net-1"
VPC_CIDR="10.0.0.1/24"
SUBNET1="sub1"
SUBNET1_IP="10.0.0.2/24"
SUBNET2="sub2"
SUBNET2_IP="10.0.0.3/24"

# ------------- STEP 1: CREATE BRIDGE (VPC) -------------
echo "🌉 Creating bridge: $VPC_NAME"
sudo ./vpcctl.py create bridge "$VPC_NAME" --ip "$VPC_CIDR"

# ------------- STEP 2: CREATE NAMESPACES (SUBNETS) -------------
echo "📦 Creating namespaces (subnets)..."
sudo ./vpcctl.py create namespace "$SUBNET1" --ip "$SUBNET1_IP" --bridge "$VPC_NAME"
sudo ./vpcctl.py create namespace "$SUBNET2" --ip "$SUBNET2_IP" --bridge "$VPC_NAME"

# ------------- STEP 3: ROUTING BETWEEN SUBNETS -------------
echo "🛣️ Setting up routing between subnets..."
sudo ./vpcctl.py set route "$SUBNET1" "$SUBNET2" "$VPC_NAME"

# ------------- STEP 4: TEST CONNECTIVITY -------------
echo "🔍 Testing connectivity between namespaces..."
sudo ip netns exec "$SUBNET1" ping -c 3 10.0.0.3

# ------------- STEP 5: ENABLE NAT (OPTIONAL) -------------
echo "🌐 Enabling NAT on $SUBNET1..."
sudo ./vpcctl.py set nat "$SUBNET1"

# ------------- STEP 6: START A SIMPLE WEB SERVER IN SUBNET1 -------------
echo "🚀 Starting web server inside $SUBNET1..."
sudo ip netns exec "$SUBNET1" python3 -m http.server 8080 &

sleep 3
echo "🌍 Curling from $SUBNET2 to $SUBNET1..."
sudo ip netns exec "$SUBNET2" curl -m 5 http://10.0.0.2:8080 || echo "Connection test failed!"

# ------------- STEP 7: SHOW STATUS -------------
echo "📊 Showing VPC Status..."
sudo ./vpcctl.py status
sudo ./vpcctl.py config

# ------------- STEP 8: CLEANUP -------------
echo "🧹 Cleaning up environment..."
sudo ./vpcctl.py delete namespace "$SUBNET1"
sudo ./vpcctl.py delete namespace "$SUBNET2"
sudo ./vpcctl.py delete bridge "$VPC_NAME"

echo "✅ Demo completed successfully!"
