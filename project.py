import tkinter as tk
from tkinter import ttk
import json
from scapy.all import sniff
from datetime import datetime
import threading

packets = []

# Function to capture packets
def packet_callback(packet):
    packet_info = {
        "timestamp": str(datetime.now()),
        "src": packet[0][1].src,
        "dst": packet[0][1].dst,
        "summary": packet.summary()
    }
    packets.append(packet_info)
    print(packet_info)

# Function to start sniffing packets
def start_sniffing():
    sniff(prn=packet_callback, count=10)  # Change count to the number of packets you want to capture
    with open('packets.json', 'w') as f:
        json.dump(packets, f, indent=4)

# GUI class
class NetworkTrafficAnalyzer:
    def _init_(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("800x600")

        self.tree = ttk.Treeview(root)
        self.tree["columns"] = ("timestamp", "src", "dst", "summary")
        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.column("timestamp", anchor=tk.W, width=140)
        self.tree.column("src", anchor=tk.W, width=120)
        self.tree.column("dst", anchor=tk.W, width=120)
        self.tree.column("summary", anchor=tk.W, width=400)

        self.tree.heading("#0", text="", anchor=tk.W)
        self.tree.heading("timestamp", text="Timestamp", anchor=tk.W)
        self.tree.heading("src", text="Source IP", anchor=tk.W)
        self.tree.heading("dst", text="Destination IP", anchor=tk.W)
        self.tree.heading("summary", text="Summary", anchor=tk.W)

        self.tree.pack(fill=tk.BOTH, expand=True)

        self.load_packets()

    def load_packets(self):
        with open('packets.json', 'r') as f:
            packets = json.load(f)

        for packet in packets:
            self.tree.insert("", "end", values=(packet["timestamp"], packet["src"], packet["dst"], packet["summary"]))

    def refresh_packets(self):
        self.tree.delete(*self.tree.get_children())
        self.load_packets()

# Function to run the sniffing in a separate thread
def run_sniffer():
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()
    sniff_thread.join()
    app.refresh_packets()

# Main function to run the GUI and sniffer
if _name_ == "_main_":
    root = tk.Tk()
    app = NetworkTrafficAnalyzer(root)
    run_sniffer()
    root.mainloop()