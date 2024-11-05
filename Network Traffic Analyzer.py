import tkinter as tk
from tkinter import messagebox, ttk
from scapy.all import sniff, wrpcap
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import psutil

# List to store captured packets
captured_packets = []

# Common ports
common_ports = [
    "80 (HTTP)", "443 (HTTPS)", "21 (FTP)", "22 (SSH)",
    "23 (Telnet)", "25 (SMTP)", "53 (DNS)", "67 (DHCP)",
    "68 (DHCP)", "110 (POP3)", "143 (IMAP)", "3306 (MySQL)",
    "5432 (PostgreSQL)", "3389 (RDP)", " "
]

# Common network interfaces
common_interfaces = ["Ethernet", "Wi-Fi"]
common_protocols = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "DHCP", "DATA", "TLS", " "]

# Function to check if the interface is active using psutil
def is_interface_active(interface):
    stats = psutil.net_if_stats()
    return stats[interface].isup if interface in stats else False

# Callback function for packet capturing
def packet_callback(packet):
    captured_packets.append(packet)
    
import ipaddress
# Function to validate IP address format
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to start packet capture and analysis
def start_capture():
    # Get IP address input
    ip_filter = ip_entry.get().strip()

    # Validate IP address format
    if ip_filter and not is_valid_ip(ip_filter):
        messagebox.showerror("Invalid IP Address", "Please enter a valid IP address format.")
        return
    # Get packet count from the input
    try:
        packet_count = int(packet_count_entry.get())
        if packet_count <= 0 or packet_count > 25:  # Limit the maximum to 25
            raise ValueError
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number of packets (1-25).")
        return

    # Get the filters from the input
    protocol_filter = protocol_combo.get().upper().strip()  # Make protocol optional
    ip_filter = ip_entry.get()
    port_filter = port_combo.get()
    interface_filter = interface_combo.get()

    # Check if the interface is selected and active
    if not interface_filter:
        messagebox.showerror("No Interface Selected", "Please select a network interface.")
        return
    if not is_interface_active(interface_filter):
        messagebox.showerror("Inactive Interface", "The selected interface is inactive. Please check your connection.")
        return

    # Clear previous data
    captured_packets.clear()

    # Capture packets
    sniff(prn=packet_callback, count=packet_count, iface=interface_filter)

    # Save captured packets to a .pcap file
    wrpcap('capture.pcap', captured_packets)

    # Analyze packets with PyShark
    cap = pyshark.FileCapture('capture.pcap')
    packet_data = []

    for pkt in cap:
        try:
            protocol = pkt.highest_layer
            source = pkt.ip.src if hasattr(pkt, 'ip') else 'N/A'
            destination = pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A'
            layers = [layer.layer_name for layer in pkt.layers]

            # Format timestamp
            timestamp = pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S')  # Format the timestamp

            # Apply filters
            if (ip_filter and (source != ip_filter)) or \
               (protocol_filter and protocol.upper() != protocol_filter) or \
               (port_filter and (str(pkt[protocol].dport) != port_filter.split(' ')[0] and str(pkt[protocol].sport) != port_filter.split(' ')[0])):
                continue

            packet_data.append({
                'Timestamp': timestamp,
                'Protocol': protocol,
                'Source': source,
                'Destination': destination,
                'Layers': ", ".join(layers)
            })
        except AttributeError:
            continue
    cap.close()

    # Create DataFrame and display results
    df = pd.DataFrame(packet_data)
    if df.empty:
        messagebox.showinfo("No Data", "No packets matched the specified filter or were captured.")
    else:
        display_table(df)

# Function to display the data in a Matplotlib table
def display_table(df):
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.axis('tight')
    ax.axis('off')
    table = ax.table(cellText=df.values, colLabels=df.columns, cellLoc='center', loc='center')

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.2)

    # Adjust the width of the timestamp column
    for (i, j), cell in table.get_celld().items():
        if j == 0:  # Timestamp column
            cell.width = 0.6  # Adjust the width to fit the content
        cell.pad = 0.1
        cell.set_text_props(ha="center", wrap=True)

    plt.title('Informations sur les paquets capturés', fontsize=14)
    plt.show()

# Function to switch to the filtering interface
def show_filter_interface():
    # Clear the first interface
    for widget in root.winfo_children():
        widget.destroy()

    # Set up the second interface
    root.geometry("805x522")
    bg_label = tk.Label(root, image=filter_bg)
    bg_label.place(relwidth=1, relheight=1)

    # Packet count input
    tk.Label(root, text="Enter number of packets to capture (max 25):").pack(pady=10)
    global packet_count_entry
    packet_count_entry = tk.Entry(root)
    packet_count_entry.pack()

    # Protocol filter input as a combobox
    tk.Label(root, text="Select protocol to filter (optional):").pack(pady=10)
    global protocol_combo
    protocol_combo = ttk.Combobox(root, values=common_protocols, state="readonly")
    protocol_combo.pack()

    # IP address filter input
    tk.Label(root, text="Enter IP address to filter (optional):").pack(pady=10)
    global ip_entry
    ip_entry = tk.Entry(root)
    ip_entry.pack()

    # Port filter input as a combobox
    tk.Label(root, text="Select port to filter (optional):").pack(pady=10)
    global port_combo
    port_combo = ttk.Combobox(root, values=common_ports, state="readonly")
    port_combo.pack()

    # Network interface filter input
    tk.Label(root, text="Select network interface (mandatory):").pack(pady=10)
    global interface_combo
    interface_combo = ttk.Combobox(root, values=common_interfaces , state="readonly")
    interface_combo.pack()

    # Start button
    start_button = tk.Button(root, text="Start Capture", command=start_capture)
    start_button.pack(pady=20)

# Setting up the GUI
root = tk.Tk()
root.title("Packet Analyzer")

# Load images
start_bg = tk.PhotoImage(file='startbackground.png')
filter_bg = tk.PhotoImage(file='filterbackground.png')
start_button_image = tk.PhotoImage(file='startpushbutton.png')

# Set up the first interface
root.geometry("411x352")
bg_label = tk.Label(root, image=start_bg)
bg_label.place(relwidth=1, relheight=1)

# Start button for the first interface
start_button = tk.Button(root, image=start_button_image, command=show_filter_interface)
start_button.place(relx=0.5, rely=0.5, anchor='center')

# Run the application
root.mainloop()
