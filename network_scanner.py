import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self):
        # Comprehensive port list - most common and vulnerable ports
        self.common_ports = {
            # Web
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            
            # Remote Access
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            5900: "VNC",
            5800: "VNC-HTTP",
            
            # File Transfer
            21: "FTP",
            20: "FTP-Data",
            69: "TFTP",
            989: "FTPS-Data",
            990: "FTPS",
            
            # Email
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            465: "SMTPS",
            587: "SMTP-Submit",
            993: "IMAPS",
            995: "POP3S",
            
            # Database
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
            1521: "Oracle",
            
            # Windows Specific
            135: "RPC",
            137: "NetBIOS-NS",
            138: "NetBIOS-DGM",
            139: "NetBIOS-SSN",
            445: "SMB",
            
            # Network Services
            53: "DNS",
            67: "DHCP-Server",
            68: "DHCP-Client",
            123: "NTP",
            161: "SNMP",
            162: "SNMP-Trap",
            389: "LDAP",
            636: "LDAPS",
            
            # Management
            8081: "HTTP-Alt2",
            9090: "Prometheus",
            9100: "Printer",
            5000: "Docker",
            8000: "HTTP-Alt3",
            
            # Vulnerable/Commonly Exploited
            2049: "NFS",
            2121: "FTP-Alt",
            2222: "SSH-Alt",
            3128: "Proxy",
            4444: "Metasploit",
            5555: "Android-ADB",
            6666: "IRC",
            6667: "IRC",
            7777: "Oracle-Web",
            8888: "HTTP-Alt4",
            9999: "Java-Console",
            
            # Industrial/IoT
            502: "Modbus",
            102: "IEC-104",
            44818: "Ethernet/IP",
            1883: "MQTT",
            8883: "MQTTS",
            
            # Gaming (often left open)
            25565: "Minecraft",
            27015: "Steam",
            27036: "Steam-Friends",
        }
    
    def resolve_hostname(self, hostname):
        """Convert domain name to IP address"""
        try:
            # Remove /32 or /24 suffix if present
            clean_host = hostname.replace('/32', '').replace('/24', '')
            ip = socket.gethostbyname(clean_host)
            return ip
        except socket.gaierror:
            return None
    
    def scan_port(self, ip, port):
        """Scan a single port on a single IP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    def scan_ip(self, ip):
        """Scan all ports on a single IP"""
        open_ports = []
        
        # Use ThreadPoolExecutor for faster scanning
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port for port in self.common_ports.keys()}
            
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append({
                        "port": port,
                        "service": self.common_ports[port]
                    })
        
        return sorted(open_ports, key=lambda x: x["port"])
    
    def scan_network(self, network_cidr):
        """Scan a network range, single IP, or domain name"""
        results = {}
        
        # Check if it's a domain name or hostname (contains letters)
        is_hostname = any(c.isalpha() for c in network_cidr)
        
        if is_hostname:
            # Handle domain name like scanme.nmap.org
            clean_host = network_cidr.replace('/32', '').replace('/24', '')
            ip = self.resolve_hostname(clean_host)
            
            if not ip:
                return {"error": f"Could not resolve hostname: {clean_host}"}
            
            open_ports = self.scan_ip(ip)
            if open_ports:
                results[f"{clean_host} ({ip})"] = open_ports
            else:
                results[f"{clean_host} ({ip})"] = []
            
            return results
        
        # Check if it's a single IP (no /)
        if '/' not in network_cidr:
            ip = network_cidr
            open_ports = self.scan_ip(ip)
            if open_ports:
                results[ip] = open_ports
            return results
        
        # Handle CIDR range (e.g., 192.168.1.0/24)
        try:
            network = ipaddress.ip_network(network_cidr, strict=False)
            
            # Limit to first 20 IPs for performance
            for ip in list(network.hosts())[:20]:
                ip_str = str(ip)
                open_ports = self.scan_ip(ip_str)
                if open_ports:
                    results[ip_str] = open_ports
            
            return results
        except ValueError as e:
            return {"error": f"Invalid network format: {str(e)}"}
    
    def scan_single_ip(self, ip):
        """Scan a single IP address or hostname"""
        # Check if it's a hostname
        if any(c.isalpha() for c in ip):
            resolved_ip = self.resolve_hostname(ip)
            if resolved_ip:
                open_ports = self.scan_ip(resolved_ip)
                return {f"{ip} ({resolved_ip})": open_ports} if open_ports else {}
            else:
                return {"error": f"Could not resolve: {ip}"}
        else:
            open_ports = self.scan_ip(ip)
            return {ip: open_ports} if open_ports else {}