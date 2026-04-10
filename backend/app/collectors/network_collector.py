import threading
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP

class NetworkCollector:
    def __init__(self, interface='eth0', filter='tcp port 80 or tcp port 443'):
        self.interface = interface
        self.filter = filter
        self.running = False
        self.thread = None
        self.callback = None
    
    def start(self, callback=None):
        self.running = True
        self.callback = callback
        self.thread = threading.Thread(target=self._collect)
        self.thread.daemon = True
        self.thread.start()
        print(f"Network collector started on interface {self.interface}")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        print("Network collector stopped")
    
    def _collect(self):
        # Use scapy for real packet capture
        def packet_handler(packet):
            if self.running and self.callback:
                packet_data = self._process_packet(packet)
                if packet_data:
                    self.callback(packet_data)
        
        # Start sniffing
        sniff(iface=self.interface, filter=self.filter, prn=packet_handler, store=False, stop_filter=lambda x: not self.running)
    
    def _process_packet(self, packet):
        # Process captured packet
        packet_data = {
            'timestamp': datetime.now().isoformat()
        }
        
        if IP in packet:
            packet_data['source_ip'] = packet[IP].src
            packet_data['target_ip'] = packet[IP].dst
            packet_data['protocol'] = packet[IP].proto
            
            # Map protocol number to name
            proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
            packet_data['protocol'] = proto_map.get(packet[IP].proto, str(packet[IP].proto))
            
            if TCP in packet:
                packet_data['source_port'] = packet[TCP].sport
                packet_data['target_port'] = packet[TCP].dport
                # Extract payload if present
                if packet[TCP].payload:
                    packet_data['payload'] = str(packet[TCP].payload)
            elif UDP in packet:
                packet_data['source_port'] = packet[UDP].sport
                packet_data['target_port'] = packet[UDP].dport
                # Extract payload if present
                if packet[UDP].payload:
                    packet_data['payload'] = str(packet[UDP].payload)
            
            # Calculate packet size
            packet_data['bytes_sent'] = len(packet)
            packet_data['bytes_received'] = 0  # For outbound packets
            packet_data['packet_count'] = 1
            packet_data['duration'] = 0.0  # Estimated
        
        return packet_data
