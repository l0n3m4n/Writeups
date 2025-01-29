from scapy.all import *
# Function to process each packet
def process_packet(pkt):
    if pkt.haslayer(ICMP):  # Check if the packet has an ICMP layer
        if pkt[ICMP].type == 0:  # Check if it's an ICMP echo reply (type 0)
            try:
                # Extract the last 4 bytes from the packet load and decode them
                data = pkt[ICMP].load[-4:]
                print(f"Received Data: {data.decode('utf-8')}", flush=True, end="")
            except UnicodeDecodeError:
                print("Non-UTF-8 data received. Skipping...", flush=True)

# Start sniffing on the "tun0" interface with a filter for ICMP packets only
sniff(iface="tun0", filter="icmp", prn=process_packet, store=0)  # store=0 prevents Scapy from storing packets in memory