import socket
import subprocess
import time
import select
from scapy.all import *
from bettercap.utils import require
from bettercap.utils.tcp import spoof, parser
from bettercap.ui import console
from bettercap.core import sniffer


HOST = '127.0.0.1' #Host IP
PORT = 22 #Port
ALLOWED_HOSTS = []
ALLOWED_PORTS = []
BLACKLISTED_IPS = []

with open('blacklist.txt', 'r') as file:
    for line in file:
        ip = line.strip()  
        BLACKLISTED_IPS.append(ip)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setblocking(0)

sock.bind((HOST, PORT))
sock.listen(5)


def is_firewall_running():
    """
    Checks if the firewall is running by inspecting the firewall status.
    Returns:
        bool: True if the firewall is active, False otherwise.
    """
    firewall_status = subprocess.check_output('sudo ufw status', shell=True)
    return 'Status: active' in firewall_status.decode('utf-8')


inputs = [sock]


def get_request_data(conn, max_size):
    """
    Receives the request data from the client.
    Args:
        conn (socket.socket): The client connection socket.
        max_size (int): The maximum size of the request to receive.
    Returns:
        str: The received request data.
    """
    request = b''
    while len(request) < max_size:
        data = conn.recv(max_size - len(request))
        if not data:
            break
        request += data
    return request.decode('utf-8')


def contains_worm(request):
    """
    Checks if the request contains a worm.
    Args:
        request (str): The request data.
    Returns:
        bool: True if the request contains a worm, False otherwise.
    """
    return 'GET /default.ida?' in request


def prevent_worm_spread(addr):
    """
    Prevents the spread of a worm by dropping the incoming connection from the address.
    Args:
        addr (tuple): The client address (IP, port).
    """
    subprocess.run(['iptables', '-A', 'INPUT', '-s', addr[0], '-j', 'DROP'])


def contains_trojan_or_botnet(request):
    """
    Checks if the request contains trojan or botnet traffic.
    Args:
        request (str): The request data.
    Returns:
        bool: True if the request contains trojan or botnet traffic, False otherwise.
    """
    return 'User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1;)' in request


def prevent_trojan_or_botnet_spread(addr, request):
    """
    Prevents the spread of trojan or botnet traffic by dropping the incoming connection from the address and sending an alert.
    Args:
        addr (tuple): The client address (IP, port).
        request (str): The request data.
    """
    subprocess.run(['echo', 'Trojan or botnet traffic detected:', request,
                    '|', 'mail', '-s', 'Firewall alert', 'security@example.com'])
    subprocess.run(['iptables', '-A', 'INPUT', '-s', addr[0], '-j', 'DROP'])


def detect_intrusion(pkt):
    """
    Detects network intrusion based on the packet.
    Args:
        pkt: The captured packet.
    """
    if pkt.haslayer(TCP) and pkt[TCP].dport == 22:
        flags = pkt[TCP].flags
        if flags & 2 and not flags & 16:
            print("SYN packet detected from {}".format(pkt[IP].src))
        elif flags & 16 and flags & 2:
            print("RST packet detected from {}".format(pkt[IP].src))


def on_packet(packet):
    """
    Callback function to process captured packets.
    Args:
        packet: The captured packet.
    """
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet.tcp.payload.load.decode('utf-8')
        if 'viagra' in payload:
            reset_pkt = IP(src=packet[IP].dst, dst=packet[IP].src)/TCP(
                dport=packet[TCP].sport, sport=packet[TCP].dport, flags='R')
            send(reset_pkt, verbose=0)
            print("Blocked spam from {}".format(packet[IP].src))
    elif packet.haslayer(TCP) and packet[TCP].dport == 22:
        flags = packet[TCP].flags
        if flags & 2 and not flags & 16:
            print("SYN packet detected from {}".format(packet[IP].src))
        elif flags & 16 and flags & 2:
            print("RST packet detected from {}".format(packet[IP].src))


sniffer.start("tcp and dst port 80", on_packet)


def idps_handler(conn, addr):
    """
    Handles the incoming connection for intrusion detection and prevention.
    Args:
        conn (socket.socket): The client connection socket.
        addr (tuple): The client address (IP, port).
    """
    if addr[0] in BLACKLISTED_IPS:
        print(f"Blocked connection from blacklisted IP: {addr[0]}")
        conn.close()
        inputs.remove(conn)
        return

    request = get_request_data(conn, 4096)

    if contains_worm(request):
        prevent_worm_spread(addr)

    if contains_trojan_or_botnet(request):
        prevent_trojan_or_botnet_spread(addr, request)

    conn.close()
    inputs.remove(conn)


def anti_jammer():
    """
    Applies anti-jammer measures by limiting and dropping ICMP echo request packets.
    """
    subprocess.run(['iptables', '-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', 'echo-request',
                    '-m', 'limit', '--limit', '1/s', '-j', 'ACCEPT'])
    subprocess.run(['iptables', '-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', 'echo-request', '-j', 'DROP'])


while True:
    readable, _, _ = select.select(inputs, [], [], 120)

    for conn in readable:
        if conn is sock:
            conn, addr = sock.accept()
            if addr[0] not in ALLOWED_HOSTS or addr[1] not in ALLOWED_PORTS:
                conn.close()
            else:
                inputs.append(conn)
        else:
            idps_handler(conn, addr)

    anti_jammer()
