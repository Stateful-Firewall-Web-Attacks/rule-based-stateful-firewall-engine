
class Rule:
    """
    A class to represent a firewall rule.

    Attributes:
        source_ip (str): Source IP address or 'any' for any IP.
        destination_ip (str): Destination IP address or 'any' for any IP.
        source_port (str): Source port or 'any' for any port.
        destination_port (str): Destination port or 'any' for any port.
        protocol (str): Protocol (e.g., TCP, UDP) or 'any' for any protocol.
        state (str): State of the connection (e.g., NEW, ESTABLISHED).
        action (str): Action to take when the rule matches (e.g., ALLOW, DENY).
        log_action (bool): Whether to log the action taken. Default is False.
        rate_limit (int or None): Rate limit for the rule. Default is None.
    """
    def __init__(self, id, source_ip, destination_ip,
                 source_port, destination_port, protocol,
                 state, action, log_action=False, rate_limit=None,
                 limit_window=None
                 ):
        self.id = id
        self.source_ip          = source_ip
        self.destination_ip     = destination_ip
        self.source_port        = source_port
        self.destination_port   = destination_port
        self.protocol           = protocol
        self.state              = state
        self.action             = action
        self.log_action         = log_action
        self.rate_limit         = rate_limit
        self.limit_window       = limit_window

    def __str__(self):
        """
        Return a string representation of the Rule object.
        """
        return (f"Rule(id={self.id}, source_ip='{self.source_ip}', destination_ip='{self.destination_ip}', "
                f"source_port='{self.source_port}', destination_port='{self.destination_port}', "
                f"protocol='{self.protocol}', state='{self.state}', action='{self.action}', "
                f"log_action={self.log_action}, rate_limit={self.rate_limit}, limit_window={self.limit_window})")

    def matches(self, packet):
        """
        Check if the packet matches the rule.

        Args:
            packet (dict): A dictionary representing a network packet with keys
                           'source_ip', 'destination_ip', 'source_port',
                           'destination_port', 'protocol', and 'state'.

        Returns:
            bool: True if the packet matches the rule, False otherwise.
        """
        return (
            (self.source_ip == packet['source_ip'] or self.source_ip == 'any') and
            (self.destination_ip == packet['destination_ip'] or self.destination_ip == 'any') and
            (self.source_port == packet['source_port'] or self.source_port == 'any') and
            (self.destination_port == packet['destination_port'] or self.destination_port == 'any') and
            (self.protocol == packet['protocol'] or self.protocol == 'any') and
            (self.state == packet['state'] or self.state == 'any')
        )
