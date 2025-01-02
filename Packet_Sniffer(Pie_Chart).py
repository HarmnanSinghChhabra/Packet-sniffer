import pyshark
import time
import plotly.graph_objects as go
from collections import defaultdict
from threading import Thread

# Define packet capture interface and settings
intF = 'Ethernet'  # Change this to your capture interface name (e.g., 'Wi-Fi')
capture = pyshark.LiveCapture(interface=intF)

# Packet statistics (to track protocol counts)
stats = defaultdict(int)  # Keeps track of packet counts by protocol
capture_duration = 60  # Duration for capturing packets in seconds (1 minute)

def capture_packets():
    """Captures packets for 1 minute and counts protocols."""
    global stats
    start_time = time.time()
    print("Capturing packets for 1 minute...")

    while time.time() - start_time < capture_duration:
        for packet in capture.sniff_continuously(packet_count=10):  # Capture packets continuously
            protocol = getattr(packet, 'highest_layer', 'UNKNOWN')
            stats[protocol] += 1  # Increment protocol count

    print(f"Capture complete! {capture_duration} seconds of packet data collected.")

def plot_pie_chart():
    """Generate a pie chart from the captured packet data."""
    protocols = list(stats.keys())
    packet_counts = list(stats.values())

    # Create a pie chart using Plotly
    fig = go.Figure(data=[go.Pie(labels=protocols, values=packet_counts, hole=0.3)])
    fig.update_layout(
        title="Protocol Distribution in Captured Packets (1 Minute)"
    )
    fig.show()

# Capture packets in a separate thread
capture_thread = Thread(target=capture_packets)
capture_thread.daemon = True
capture_thread.start()

# Wait for packet capture to complete
time.sleep(capture_duration)

# Plot the pie chart after capturing
plot_pie_chart()
