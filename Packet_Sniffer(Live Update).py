import pyshark
import json
import time
import plotly.graph_objects as go
from collections import defaultdict
from threading import Thread

# Define packet structure
class pckt:
    def __init__(self, sniff_timestamp: str = '', layer: str = '', srcPort: str = '', dstPort: str = '', ipSrc: str = '', ipDst: str = '', highest_layer=''):
        self.sniff_timestamp = sniff_timestamp
        self.layer = layer
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.ipSrc = ipSrc
        self.ipDst = ipDst
        self.highest_layer = highest_layer


# Define packet capture interface and settings
intF = 'Ethernet'  # Change this to your capture interface name (e.g., 'Wi-Fi')
capture = pyshark.LiveCapture(interface=intF)

# Packet statistics (to track protocol counts and traffic volume)
stats = defaultdict(int)  # Keeps track of packet counts by protocol
traffic_data = defaultdict(int)  # Tracks bytes per protocol

# Buffer to accumulate packet statistics
packet_buffer = []
packet_count = 0  # To track how many packets have been processed

def update_graph():
    """This function will be used to update the graph periodically."""
    global stats, traffic_data, packet_count

    while True:
        if packet_count >= 10:  # Only update after 10 packets
            time.sleep(1)  # Wait before refreshing

            # Prepare the data to be plotted
            protocols = list(stats.keys())
            packet_counts = list(stats.values())
            traffic_volumes = [traffic_data[proto] for proto in protocols]

            # Create a new figure each time
            fig = go.Figure()
            fig.add_trace(go.Bar(name='Packet Count', x=protocols, y=packet_counts, marker_color='blue'))
            fig.add_trace(go.Scatter(name='Traffic Volume (bytes)', x=protocols, y=traffic_volumes, mode='lines+markers', marker_color='red'))

            fig.update_layout(
                title="Real-Time Packet Capture Analysis",
                xaxis_title="Protocol",
                yaxis_title="Count/Bytes",
                showlegend=True
            )

            # Show the figure in a new browser tab
            fig.show()

            # Reset the stats and packet count for the next group of 10 packets
            stats.clear()
            traffic_data.clear()
            packet_count = 0

def packet_filter(packet):
    """Function to filter and process packets."""
    global packet_count
    try:
        # Default protocol is unknown
        protocol = getattr(packet, 'highest_layer', 'UNKNOWN')
        transport_layer = getattr(packet, 'transport_layer', 'N/A')

        # Increment protocol count
        stats[protocol] += 1

        # Increment traffic volume if the packet has a length
        if hasattr(packet, 'length'):
            traffic_data[protocol] += int(packet.length)

        # Create a packet object to store details
        p = pckt()
        p.sniff_timestamp = getattr(packet, 'sniff_timestamp', 'N/A')
        p.highest_layer = protocol
        p.layer = transport_layer

        # Add IP details if available
        if hasattr(packet, 'ip'):
            p.ipSrc = packet.ip.src
            p.ipDst = packet.ip.dst
        else:
            p.ipSrc = "N/A"
            p.ipDst = "N/A"

        # Add port details if TCP or UDP is present
        if hasattr(packet, 'tcp'):
            p.srcPort = getattr(packet.tcp, 'srcport', 'N/A')
            p.dstPort = getattr(packet.tcp, 'dstport', 'N/A')
        elif hasattr(packet, 'udp'):
            p.srcPort = getattr(packet.udp, 'srcport', 'N/A')
            p.dstPort = getattr(packet.udp, 'dstport', 'N/A')
        else:
            p.srcPort = "N/A"
            p.dstPort = "N/A"

        # Print packet details for debugging
        print(f"Captured Packet: {json.dumps(p.__dict__, indent=2)}")

        # Store packet data in the buffer
        packet_buffer.append(p)
        packet_count += 1  # Increment the packet counter

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start capturing packets in a separate thread
def start_capture():
    """Function to start packet capture."""
    print("Starting live packet capture. Graph will update in real-time.")
    for packet in capture.sniff_continuously():
        packet_filter(packet)

# Run the packet capture in a separate thread
capture_thread = Thread(target=start_capture)
capture_thread.daemon = True
capture_thread.start()

# Run the graph update loop
update_graph()  # This will run indefinitely until the script is stopped
