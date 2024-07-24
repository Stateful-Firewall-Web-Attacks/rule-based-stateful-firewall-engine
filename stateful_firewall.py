import ipaddress
import subprocess
from config import *
from rule import Rule
from logger import Logger
from scapy.all import TCP, IP, ICMP, ARP, sniff
from intrusion_detection import IntrusionDetection

class StatefulFirewall:
    def __init__(self, rules: list[Rule], intrusion_detection: IntrusionDetection, logger: Logger):
        self.rules = rules
        self.logger = logger
        self.machine_log = {}
        self.state_table = {}
        self.intrusion_detection = intrusion_detection

    def update_rules(self, rules: list[Rule]):
        """
        Update the list of firewall rules.

        Args:
            rules (list[Rule]): A list of Rule objects to replace the current rules.
        """
        self.rules = rules
        self.logger.log("Firewall rules have been updated.")


    def check_packet(self, packet) -> str:
        """
        Check the packet against the firewall rules and return the action to take.

        Args:
            packet (Packet): The packet to check.

        Returns:
            str: The action to take (e.g., 'ALLOW', 'DENY').
        """
        src_ip, dst_ip, src_port, dst_port, protocol, state = self.extract_packet_info(packet)
        
        packet_info = {
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'protocol': protocol,
            'state': state
        }

        try:
            self.intrusion_detection.detect_intrusions(packet_info)
        except RuntimeError as e:
            intrusion_info = e.args[0]
            attack_id = intrusion_info['id']
            message = intrusion_info['msg']
            self.logger.log(message)
            if attack_id in [syn_flood_id, icmp_flood_id, ip_spoofing_id]:
                self.add_blackhole_route(src_ip)
            return 'DENY'
        
        for rule in self.rules:
            if rule.matches(packet_info):
                if rule.log_action:
                    self.log_packet(packet_info, rule.action)
                
                if rule.rate_limit:
                    if not self.check_rate_limit(rule):
                        self.logger.log(f"Rate limit exceeded for {packet_info['source_ip']} to {packet_info['destination_ip']}")
                        return 'DENY'

                return rule.action
            
        return 'ALLOW'

    def log_packet(self, packet_info, action):
        """
        Log the action taken on the packet.

        Args:
            packet_info (dict): The packet information being logged.
            action (str): The action taken on the packet.
        """
        self.logger.log(f"Packet {packet_info} action: {action}")

    def extract_packet_info(self, packet):
        """
        Extract relevant information from the packet.

        Args:
            packet (Packet): The packet to extract information from.

        Returns:
            tuple: (src_ip, dst_ip, src_port, dst_port, protocol, state)
        """
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            connection = (src_ip, dst_ip, src_port, dst_port)
            state = self.update_connection_state(packet, connection)

            return src_ip, dst_ip, src_port, dst_port, 'TCP', state

        elif packet.haslayer(ICMP):
            ip_layer = packet[IP]
            icmp_layer = packet[ICMP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = 'any'
            dst_port = 'any'

            if icmp_layer.type == 8:  # Echo Request
                state = 'ICMP echo'
            elif icmp_layer.type == 0:  # Echo Reply
                state = 'ICMP reply wait'
            else:
                state = 'Invalid'

            connection = (src_ip, dst_ip, src_port, dst_port)
            self.state_table[connection] = state

            # Update ICMP flood detection
            self.intrusion_detection.update_icmp_count(src_ip)

            return src_ip, dst_ip, src_port, dst_port, 'ICMP', state

        elif packet.haslayer(ARP):
            arp_layer = packet[ARP]

            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            src_port = 'any'
            dst_port = 'any'

            if arp_layer.op == 1:  # who-has (request)
                state = 'ARP request'
            elif arp_layer.op == 2:  # is-at (reply)
                state = 'ARP reply'
            else:
                state = 'Invalid'

            connection = (src_ip, dst_ip, src_port, dst_port)
            self.state_table[connection] = state

            return src_ip, dst_ip, src_port, dst_port, 'ARP', state

        return None, None, None, None, None, 'Invalid'

    def update_connection_state(self, packet, connection):
        """
        Update the connection state based on the packet.

        Args:
            packet (Packet): The packet to use for updating the state.
            connection (tuple): The connection key.

        Returns:
            str: The updated state of the connection.
        """
        tcp_layer = packet[TCP]

        if connection not in self.machine_log:
            self.machine_log[connection] = {
                'current': 'NEW',
                'previous': [],
                'future': ['SYN_SENT', 'SYN_RECEIVED', 'ESTABLISHED', 'FIN_WAIT', 'CLOSED']
            }
            self.state_table[connection] = 'NEW'

        current_state = self.machine_log[connection]['current']

        if tcp_layer.flags == 'S':  # SYN
            new_state = 'SYN_SENT'
            if self.intrusion_detection.detect_syn_flood(packet["source_ip"]):
                self.logger.log(f"SYN flood attempt detected from IP: {packet["source_ip"]}")
                self.add_blackhole_route(packet["source_ip"])
                return 'Invalid'
        elif tcp_layer.flags == 'SA':  # SYN-ACK
            new_state = 'SYN_RECEIVED'
        elif tcp_layer.flags == 'A':  # ACK
            if current_state == 'SYN_RECEIVED':
                new_state = 'ESTABLISHED'
            else:
                new_state = 'Invalid'
        elif tcp_layer.flags == 'F':  # FIN
            new_state = 'FIN_WAIT'
        elif tcp_layer.flags == 'R':  # RST
            new_state = 'CLOSED'
        else:
            new_state = 'Invalid'

        # Update the state in machine_log and log the status
        if new_state != 'Invalid':
            if current_state not in self.machine_log[connection]['previous']:
                self.machine_log[connection]['previous'].append(current_state)
            self.machine_log[connection]['current'] = new_state
            if new_state in self.machine_log[connection]['future']:
                self.machine_log[connection]['future'].remove(new_state)
            
            future_states = ', '.join(self.machine_log[connection]['future'])
            self.logger.log(f"Connection {connection}: State changed from {current_state} to {new_state}. Future states: {future_states}")
        else:
            self.logger.log(f"Connection {connection}: Received invalid state transition with flags {tcp_layer.flags}")
            
        return self.machine_log[connection]['current']
    
    def add_blackhole_route(self, ip: str):
        """
        Add a blackhole route for the specified IP address.

        Args:
            ip (str): The IP address to add a blackhole route for.

        Raises:
            ValueError: If the provided IP address is not valid.
            subprocess.CalledProcessError: If the command to add the blackhole route fails.
        """
        try:
            # Check if the IP address is valid
            ip_obj = ipaddress.ip_address(ip)
            # Execute the ip route command to add a blackhole route
            subprocess.run(["sudo", "ip", "route", "add", str(ip_obj), "via", "blackhole"], check=True)
            self.logger.log(f"Blackhole route added for IP: {ip}")
        except ValueError:
            self.logger.log("Invalid IP address")
        except subprocess.CalledProcessError as e:
            self.logger.log(f"Failed to add blackhole route: {e}")

    def perform_stateful_inspection(self, packet):
        """
        Process the packet received from NetfilterQueue.

        Args:
            packet (netfilterqueue.Packet): The packet to process.
        """
        scapy_packet = IP(packet.get_payload())
        action = self.check_packet(scapy_packet)
        if action == 'DENY':
            packet.drop()
        else:
            packet.accept()