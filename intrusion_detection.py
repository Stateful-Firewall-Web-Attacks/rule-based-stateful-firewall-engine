import time
from config import *
from rule import Rule
from collections import defaultdict
from scapy.all import TCP, IP, ARP, Ether

class IntrusionDetection:
    def __init__(self, syn_flood_threshold=100, syn_time_window=60, 
                 port_scan_threshold=20, port_scan_time_window=60, 
                 icmp_flood_threshold=100, icmp_time_window=60):
        self.syn_count              =   defaultdict(list)
        self.syn_flood_threshold    =   syn_flood_threshold
        self.syn_time_window        =   syn_time_window
        self.ip_mac_map             =   {}  # Map of IP addresses to MAC addresses
        self.port_scan_attempts     =   defaultdict(list)
        self.port_scan_threshold    =   port_scan_threshold
        self.port_scan_time_window  =   port_scan_time_window
        self.icmp_count             =   defaultdict(list)
        self.icmp_flood_threshold   =   icmp_flood_threshold
        self.icmp_time_window       =   icmp_time_window
        self.packet_counts          =   defaultdict(list)
        self.blackholed_ips         =   set()

    def update_settings(self, settings):
        """
        Update the intrusion detection settings with new values.

        Args:
            settings (dict): Dictionary containing new settings values.
        """
        self.syn_flood_threshold    =   settings['syn_flood_threshold']
        self.syn_time_window        =   settings['syn_time_window']
        self.port_scan_threshold    =   settings['port_scan_threshold']
        self.port_scan_time_window  =   settings['port_scan_time_window']
        self.icmp_flood_threshold   =   settings['icmp_flood_threshold']
        self.icmp_time_window       =   settings['icmp_time_window']


    def detect_syn_flood(self, src_ip):
        """
        Detect a potential SYN flood attack.

        Args:
            src_ip (str): Source IP address to monitor.
        """
        current_time = time.time()
        self.syn_count[src_ip].append(current_time)
        
        # Remove timestamps older than the time window
        self.syn_count[src_ip] = [timestamp for timestamp in self.syn_count[src_ip] if current_time - timestamp <= self.syn_time_window]
        
        # Check if the number of SYN packets exceeds the threshold
        if len(self.syn_count[src_ip]) > self.syn_flood_threshold:
            self.blackholed_ips.add(src_ip)
            return True
        return False

    def detect_ip_spoofing(self, packet):
        """
        Detect a potential IP spoofing attack.

        Args:
            packet (Packet): The packet to check.

        Returns:
            bool: True if IP spoofing is detected, False otherwise.
        """
        if packet.haslayer(Ether) and packet.haslayer(IP):
            eth_layer = packet[Ether]
            ip_layer = packet[IP]
            
            src_ip = ip_layer.src
            src_mac = eth_layer.src

            if src_ip in self.ip_mac_map:
                if self.ip_mac_map[src_ip] != src_mac:
                    return True
            else:
                self.ip_mac_map[src_ip] = src_mac
        
        return False

    def detect_tcp_scan(self, packet):
        """
        Detect a potential TCP scan.

        Args:
            packet (Packet): The packet to check.

        Returns:
            bool: True if TCP scan is detected, False otherwise.
        """
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]

            src_ip = ip_layer.src
            dst_port = tcp_layer.dport
            current_time = time.time()
            
            self.port_scan_attempts[src_ip].append((dst_port, current_time))
            
            # Remove attempts older than the time window
            self.port_scan_attempts[src_ip] = [(port, timestamp) for port, timestamp in self.port_scan_attempts[src_ip] if current_time - timestamp <= self.port_scan_time_window]
            
            # Check if the number of unique ports exceeds the threshold
            unique_ports = set(port for port, timestamp in self.port_scan_attempts[src_ip])
            if len(unique_ports) > self.port_scan_threshold:
                return True
        
        return False

    def detect_arp_spoofing(self, packet):
        """
        Detect a potential ARP spoofing attack.

        Args:
            packet (Packet): The packet to check.

        Returns:
            bool: True if ARP spoofing is detected, False otherwise.
        """
        if packet.haslayer(ARP):
            arp_layer = packet[ARP]

            src_ip = arp_layer.psrc
            src_mac = packet[Ether].src

            if src_ip in self.ip_mac_map:
                if self.ip_mac_map[src_ip] != src_mac:
                    return True
            else:
                self.ip_mac_map[src_ip] = src_mac

        return False

    def update_icmp_count(self, src_ip):
        """
        Update the ICMP packet count for the source IP.

        Args:
            src_ip (str): Source IP address to monitor.
        """
        current_time = time.time()
        self.icmp_count[src_ip].append(current_time)
        
        # Remove timestamps older than the time window
        self.icmp_count[src_ip] = [timestamp for timestamp in self.icmp_count[src_ip] if current_time - timestamp <= self.icmp_time_window]

    def detect_icmp_flood(self, src_ip):
        """
        Detect a potential ICMP flood attack.

        Args:
            src_ip (str): Source IP address to monitor.

        Returns:
            bool: True if ICMP flood is detected, False otherwise.
        """
        if len(self.icmp_count[src_ip]) > self.icmp_flood_threshold:
            self.blackholed_ips.add(src_ip)
            return True
        return False
    
    def check_rate_limit(self, rule: Rule):
        """
        Check if the packet complies with the rate limit for the rule.

        Args:
            rule (Rule): The rule being checked.

        Returns:
            bool: True if the packet complies with the rate limit, False otherwise.
        """
        current_time = time.time()
        key = (rule.source_ip, rule.destination_ip, rule.protocol, rule.state)

        # Add current timestamp to the list of packet timestamps for the key
        self.packet_counts[key].append(current_time)

        # Remove timestamps older than the rule's rate limit time window
        self.packet_counts[key] = [timestamp for timestamp in self.packet_counts[key] if current_time - timestamp <= rule.limit_window]

        # Check if the number of packets in the time window exceeds the rate limit
        if len(self.packet_counts[key]) > rule.rate_limit:
            return False

        return True
    
    def is_blacklisted(self, src_ip):
        """
        Check if the source IP is blacklisted.

        Args:
            src_ip (str): Source IP address to check.

        Returns:
            bool: True if the IP is blacklisted, False otherwise.
        """
        return src_ip in self.blackholed_ips
    
    def detect_intrusions(self, packet):
        """
        Run various intrusion detection checks on the given network packet.

        Args:
            packet (dict): The network packet to check. Must contain at least the "source_ip" key.

        Raises:
            RuntimeError: If any intrusion is detected, a RuntimeError is raised with a dictionary
                        containing the attack id and a message describing the attack.
        """
        if packet["protocol"] == "TCP" and self.is_blacklisted(packet["source_ip"]):
            raise RuntimeError({"id": 0, "msg": f"Traffic from blackholed IP {packet["source_ip"]} is dropped."})
        
        if packet["protocol"] == "ICMP" and self.detect_icmp_flood(packet["source_ip"]):
            raise RuntimeError({"id": icmp_flood_id, "msg": f"ICMP flood attack detected from IP: {packet["source_ip"]}"})
        
        if packet["protocol"] == "TCP" and self.detect_ip_spoofing(packet):
            raise RuntimeError({"id": ip_spoofing_id, "msg": f"IP spoofing attempt detected from IP: {packet["source_ip"]}"})
        
        if packet["protocol"] == "ARP" and self.detect_arp_spoofing(packet):
            raise RuntimeError({"id": arp_spoofing_id, "msg": f"ARP spoofing attempt detected from IP: {packet["source_ip"]}"})
        
        if packet["protocol"] == "TCP" and self.detect_tcp_scan(packet):
            raise RuntimeError({"id": tcp_scan_id, "msg": f"TCP scan attempt detected from IP: {packet["source_ip"]}"})
