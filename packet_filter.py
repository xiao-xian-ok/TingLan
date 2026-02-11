def filter_by_protocol(packets, protocol):
    protocol = protocol.lower()
    for pkt in packets:
        if hasattr(pkt, protocol):
            yield pkt


def read_http_packet(packet):
    return filter_by_protocol(packet, 'HTTP')

def read_tcp_packet(packet):
    return filter_by_protocol(packet, 'TCP')

def read_udp_packet(packet):
    return filter_by_protocol(packet, 'UDP')

def read_icmp_packet(packet):
    return filter_by_protocol(packet, 'ICMP')

def read_arp_packet(packet):
    return filter_by_protocol(packet, 'ARP')

def read_ftp_packet(packet):
    return filter_by_protocol(packet, 'FTP')

def read_ssh_packet(packet):
    return filter_by_protocol(packet, 'SSH')

def read_smtp_packet(packet):
    return filter_by_protocol(packet, 'SMTP')