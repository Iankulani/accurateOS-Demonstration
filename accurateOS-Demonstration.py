"""
ACCURATE ONLINE OS DEMO - ENHANCED VERSION
Author: Ian Carter Kulani
Version: Demo
"""

import socket
import threading
import time
import requests
import json
import subprocess
import os
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
import sys
import random
import platform
import psutil
import getpass
import hashlib
import sqlite3
from pathlib import Path
import ipaddress
import re
import shutil

# Simplified imports for core functionality
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("Warning: python-nmap not available. Some scan features will be limited.")

# Configuration
CONFIG_FILE = "cyber_security_config.json"
DATABASE_FILE = "network_data.db"
REPORT_DIR = "reports"

class TracerouteTool:
    """Enhanced interactive traceroute tool"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        # Simple hostname validation regex
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]  # -d avoids DNS resolution for speed

        # On Unix-like systems
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute/tracepath/ping utilities found on this system.')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)  # Real-time output

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled. Terminating traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error running command: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        # Validate target
        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        # Limit output for Telegram
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

    def prompt_target(self) -> Optional[str]:
        """Prompt user for target (for standalone use)"""
        while True:
            user_input = input('Enter target IP address or hostname to traceroute (or type "quit" to exit): ').strip()
            if not user_input:
                print('Please enter a non-empty value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None

            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP address or hostname. Examples: 8.8.8.8, 2001:4860:4860::8888, example.com')

class DatabaseManager:
    """Manage SQLite database for storing network data and threats"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # IP monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP
            )
        ''')
        
        # Threat detection table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        # Command history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        # Network scan results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Traceroute results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traceroute_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT,
                execution_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success) VALUES (?, ?, ?)',
            (command, source, success)
        )
        conn.commit()
        conn.close()
    
    def log_traceroute(self, target: str, command: str, output: str, execution_time: float):
        """Log traceroute results to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO traceroute_results (target, command, output, execution_time) VALUES (?, ?, ?, ?)',
            (target, command, output, execution_time)
        )
        conn.commit()
        conn.close()
    
    def get_command_history(self, limit: int = 50) -> List[Tuple]:
        """Get command history from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT command, source, timestamp, success FROM command_history ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str = ""):
        """Log threat detection to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO threat_logs (ip_address, threat_type, severity, description) VALUES (?, ?, ?, ?)',
            (ip_address, threat_type, severity, description)
        )
        conn.commit()
        conn.close()
    
    def get_recent_threats(self, limit: int = 20) -> List[Tuple]:
        """Get recent threats from database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT ip_address, threat_type, severity, timestamp FROM threat_logs ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results

class NetworkScanner:
    """Network scanning capabilities"""
    
    def __init__(self):
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
        self.traceroute_tool = TracerouteTool()
    
    def ping_ip(self, ip: str) -> str:
        """Simple ping that works reliably"""
        try:
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '4', ip]
            else:  # Linux/Mac
                cmd = ['ping', '-c', '4', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Ping timeout for {ip}"
        except Exception as e:
            return f"Ping error: {str(e)}"
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute using the dedicated tool"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform port scan"""
        if self.nm:
            try:
                self.nm.scan(ip, ports, arguments='-T4')
                open_ports = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                open_ports.append({
                                    'port': port,
                                    'state': self.nm[ip][proto][port]['state'],
                                    'service': self.nm[ip][proto][port].get('name', 'unknown')
                                })
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'scan_time': datetime.now().isoformat()
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def get_ip_location(self, ip: str) -> str:
        """Get IP location using ip-api.com"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    return json.dumps({
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A')
                    }, indent=2)
                else:
                    return f"Location error: {data.get('message', 'Unknown error')}"
            else:
                return f"Location error: HTTP {response.status_code}"
        except Exception as e:
            return f"Location error: {str(e)}"

class TelegramBotHandler:
    """Enhanced Telegram bot handler"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.last_update_id = 0
        self.command_handlers = self.setup_command_handlers()
    
    def setup_command_handlers(self) -> Dict[str, callable]:
        """Setup comprehensive command handlers"""
        return {
            '/start': self.handle_start,
            '/help': self.handle_help,
            '/ping_ip': self.handle_ping_ip,
            '/start_monitoring_ip': self.handle_start_monitoring_ip,
            '/stop': self.handle_stop,
            '/history': self.handle_history,
            '/add_ip': self.handle_add_ip,
            '/remove_ip': self.handle_remove_ip,
            '/list_ips': self.handle_list_ips,
            '/clear': self.handle_clear,
            '/tracert_ip': self.handle_tracert_ip,
            '/traceroute_ip': self.handle_traceroute_ip,
            '/scan_ip': self.handle_scan_ip,
            '/location_ip': self.handle_location_ip,
            '/analyze_ip': self.handle_analyze_ip,
            '/status': self.handle_status,
            '/curl': self.handle_curl,
            '/whois': self.handle_whois,
            '/dns_lookup': self.handle_dns_lookup,
            '/network_info': self.handle_network_info,
            '/system_info': self.handle_system_info,
            '/threat_summary': self.handle_threat_summary,
            '/generate_report': self.handle_generate_report,
            '/advanced_traceroute': self.handle_advanced_traceroute
        }
    
    def send_telegram_message(self, message: str, parse_mode: str = 'HTML') -> bool:
        """Send message to Telegram"""
        if not self.monitor.telegram_token or not self.monitor.telegram_chat_id:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/sendMessage"
            
            # Split long messages
            if len(message) > 4096:
                messages = [message[i:i+4096] for i in range(0, len(message), 4096)]
                for msg in messages:
                    payload = {
                        'chat_id': self.monitor.telegram_chat_id,
                        'text': msg,
                        'parse_mode': parse_mode,
                        'disable_web_page_preview': True
                    }
                    response = requests.post(url, json=payload, timeout=30)
                    if response.status_code != 200:
                        return False
                    time.sleep(0.5)
                return True
            else:
                payload = {
                    'chat_id': self.monitor.telegram_chat_id,
                    'text': message,
                    'parse_mode': parse_mode,
                    'disable_web_page_preview': True
                }
                response = requests.post(url, json=payload, timeout=30)
                return response.status_code == 200
        except Exception as e:
            logging.error(f"Telegram send error: {e}")
            return False
    
    def handle_start(self, args: List[str]) -> str:
        """Handle /start command"""
        return """
🚀 <b>accurateOS Demo - Enhanced Edition v2</b> 🚀

Welcome! Your cybersecurity assistant is ready.

🔍 <b>Network Commands</b>
/ping_ip [IP] - Ping IP address
/tracert_ip [IP] - Traceroute (Windows)
/traceroute_ip [IP] - Traceroute (Linux/Mac)
/advanced_traceroute [IP] - Enhanced traceroute
/scan_ip [IP] - Port scan
/location_ip [IP] - Get IP location
/analyze_ip [IP] - Analyze IP threats
/whois [domain] - WHOIS lookup
/dns_lookup [domain] - DNS lookup

📊 <b>Monitoring</b>
/start_monitoring_ip [IP] - Start monitoring
/stop - Stop all monitoring
/add_ip [IP] - Add IP to list
/remove_ip [IP] - Remove IP
/list_ips - List monitored IPs
/threat_summary - Recent threats

💻 <b>System</b>
/network_info - Network information
/system_info - System information
/status - System status
/history - Command history
/clear - Clear history

📡 <b>Web Tools</b>
/curl [URL] - HTTP request
/generate_report - Generate security report

❓ Type /help for detailed usage!
        """
    
    def handle_help(self, args: List[str]) -> str:
        """Show help"""
        return """
<b>🔒 Complete Command Reference</b>

<b>🌐 Network Diagnostics:</b>
<code>/ping_ip 8.8.8.8</code>
<code>/tracert_ip google.com</code>
<code>/traceroute_ip example.com</code>
<code>/advanced_traceroute 1.1.1.1</code>
<code>/scan_ip 192.168.1.1</code>
<code>/location_ip 1.1.1.1</code>
<code>/whois malawi.com</code>
<code>/dns_lookup example.com</code>

<b>🛡️ Security Analysis:</b>
<code>/analyze_ip 192.168.1.1</code>
<code>/threat_summary</code>
<code>/generate_report</code>

<b>📊 Monitoring:</b>
<code>/start_monitoring_ip 192.168.1.1</code>
<code>/add_ip 10.0.0.1</code>
<code>/remove_ip 10.0.0.1</code>
<code>/list_ips</code>
<code>/stop</code>

<b>💻 System Info:</b>
<code>/network_info</code>
<code>/system_info</code>
<code>/status</code>

<b>🌍 Web Tools:</b>
<code>/curl https://api.github.com</code>

All commands execute instantly! 🚀
        """
    
    def handle_ping_ip(self, args: List[str]) -> str:
        """Handle ping"""
        if not args:
            return "❌ Usage: <code>/ping_ip [IP]</code>"
        
        ip = args[0]
        result = self.monitor.scanner.ping_ip(ip)
        return f"🏓 <b>Ping {ip}</b>\n\n<code>{result[-1000:]}</code>"
    
    def handle_start_monitoring_ip(self, args: List[str]) -> str:
        """Handle start monitoring"""
        if not args:
            return "❌ Usage: <code>/start_monitoring_ip [IP]</code>"
        
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitor.monitored_ips.add(ip)
            self.monitor.save_config()
            self.monitor.db_manager.log_command(f"start_monitoring_ip {ip}", 'telegram', True)
            return f"✅ Started monitoring <code>{ip}</code>"
        except ValueError:
            return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_stop(self, args: List[str]) -> str:
        """Handle stop"""
        if not self.monitor.monitored_ips:
            return "⚠️ No IPs are being monitored"
        
        ips = list(self.monitor.monitored_ips)
        self.monitor.monitored_ips.clear()
        self.monitor.save_config()
        return f"🛑 Stopped monitoring: {', '.join(ips)}"
    
    def handle_history(self, args: List[str]) -> str:
        """Handle history"""
        history = self.monitor.db_manager.get_command_history(20)
        if not history:
            return "📝 No commands recorded"
        
        response = "📝 <b>Command History</b>\n\n"
        for i, (cmd, src, ts, success) in enumerate(history, 1):
            status = "✅" if success else "❌"
            response += f"{i}. {status} <code>{cmd}</code>\n   {src} | {ts}\n\n"
        return response
    
    def handle_add_ip(self, args: List[str]) -> str:
        """Handle add IP"""
        if not args:
            return "❌ Usage: <code>/add_ip [IP]</code>"
        
        ip = args[0]
        try:
            ipaddress.ip_address(ip)
            self.monitor.monitored_ips.add(ip)
            self.monitor.save_config()
            return f"✅ Added <code>{ip}</code>"
        except ValueError:
            return f"❌ Invalid IP: <code>{ip}</code>"
    
    def handle_remove_ip(self, args: List[str]) -> str:
        """Handle remove IP"""
        if not args:
            return "❌ Usage: <code>/remove_ip [IP]</code>"
        
        ip = args[0]
        if ip in self.monitor.monitored_ips:
            self.monitor.monitored_ips.remove(ip)
            self.monitor.save_config()
            return f"✅ Removed <code>{ip}</code>"
        return f"❌ IP not in list: <code>{ip}</code>"
    
    def handle_list_ips(self, args: List[str]) -> str:
        """Handle list IPs"""
        if not self.monitor.monitored_ips:
            return "📋 No IPs are being monitored"
        
        response = "📋 <b>Monitored IPs</b>\n\n"
        for ip in sorted(self.monitor.monitored_ips):
            response += f"• <code>{ip}</code>\n"
        return response
    
    def handle_clear(self, args: List[str]) -> str:
        """Handle clear"""
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM command_history')
        conn.commit()
        conn.close()
        return "✅ Command history cleared"
    
    def handle_tracert_ip(self, args: List[str]) -> str:
        """Handle tracert"""
        if not args:
            return "❌ Usage: <code>/tracert_ip [IP/domain]</code>"
        
        target = args[0]
        result = self.monitor.scanner.traceroute(target)
        return result
    
    def handle_traceroute_ip(self, args: List[str]) -> str:
        """Handle traceroute"""
        return self.handle_tracert_ip(args)
    
    def handle_advanced_traceroute(self, args: List[str]) -> str:
        """Handle advanced traceroute with enhanced features"""
        if not args:
            return "❌ Usage: <code>/advanced_traceroute [IP/domain]</code>"
        
        target = args[0]
        self.send_telegram_message(f"🛣️ <b>Starting advanced traceroute to {target}</b>...")
        
        # Run enhanced traceroute
        result = self.monitor.scanner.traceroute(target)
        return result
    
    def handle_scan_ip(self, args: List[str]) -> str:
        """Handle scan"""
        if not args:
            return "❌ Usage: <code>/scan_ip [IP]</code>"
        
        ip = args[0]
        self.send_telegram_message(f"🔍 Scanning <code>{ip}</code>...")
        
        result = self.monitor.scanner.port_scan(ip)
        if result['success']:
            open_ports = result.get('open_ports', [])
            response = f"🔍 <b>Scan Results: {ip}</b>\n\n"
            response += f"Open Ports: {len(open_ports)}\n\n"
            
            if open_ports:
                for p in open_ports[:10]:
                    response += f"• Port {p['port']}: {p['service']}\n"
                if len(open_ports) > 10:
                    response += f"\n... and {len(open_ports)-10} more"
            else:
                response += "🔒 No open ports found"
            return response
        return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def handle_location_ip(self, args: List[str]) -> str:
        """Handle location"""
        if not args:
            return "❌ Usage: <code>/location_ip [IP]</code>"
        
        ip = args[0]
        result = self.monitor.scanner.get_ip_location(ip)
        return f"🌍 <b>Location: {ip}</b>\n\n<code>{result}</code>"
    
    def handle_analyze_ip(self, args: List[str]) -> str:
        """Handle analyze"""
        if not args:
            return "❌ Usage: <code>/analyze_ip [IP]</code>"
        
        ip = args[0]
        response = f"🔍 <b>Analysis: {ip}</b>\n\n"
        
        # Get location
        location = self.monitor.scanner.get_ip_location(ip)
        try:
            loc_data = json.loads(location)
            response += f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}\n"
            response += f"🏢 ISP: {loc_data.get('isp', 'N/A')}\n\n"
        except:
            pass
        
        # Check threats
        threats = self.monitor.db_manager.get_recent_threats(5)
        ip_threats = [t for t in threats if t[0] == ip]
        
        if ip_threats:
            response += f"🚨 <b>Threats Found: {len(ip_threats)}</b>\n"
            for threat in ip_threats:
                response += f"• {threat[1]}: {threat[2]}\n"
        else:
            response += "✅ No recent threats detected"
        
        return response
    
    def handle_status(self, args: List[str]) -> str:
        """Handle status"""
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        
        response = "📊 <b>System Status</b>\n\n"
        response += f"✅ Bot: Online\n"
        response += f"🔍 Monitored IPs: {len(self.monitor.monitored_ips)}\n"
        response += f"💻 CPU: {cpu}%\n"
        response += f"🧠 Memory: {mem.percent}%\n"
        response += f"🌐 Connections: {len(psutil.net_connections())}\n"
        return response
    
    def handle_curl(self, args: List[str]) -> str:
        """Handle curl"""
        if not args:
            return "❌ Usage: <code>/curl [URL]</code>"
        
        url = args[-1]
        try:
            response = requests.get(url, timeout=10)
            result = f"📡 <b>CURL Response</b>\n\n"
            result += f"Status: {response.status_code}\n"
            result += f"Size: {len(response.content)} bytes\n\n"
            
            preview = response.text[:500]
            result += f"<code>{preview}</code>"
            if len(response.text) > 500:
                result += "..."
            
            return result
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def handle_whois(self, args: List[str]) -> str:
        """Handle whois"""
        if not args:
            return "❌ Usage: <code>/whois [domain]</code>"
        
        domain = args[0]
        try:
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
            output = result.stdout[:1000]
            return f"🔍 <b>WHOIS: {domain}</b>\n\n<code>{output}</code>"
        except:
            return "❌ WHOIS lookup failed"
    
    def handle_dns_lookup(self, args: List[str]) -> str:
        """Handle DNS lookup"""
        if not args:
            return "❌ Usage: <code>/dns_lookup [domain]</code>"
        
        domain = args[0]
        try:
            ip = socket.gethostbyname(domain)
            return f"🌐 <b>DNS Lookup</b>\n\n{domain} → <code>{ip}</code>"
        except Exception as e:
            return f"❌ DNS lookup failed: {str(e)}"
    
    def handle_network_info(self, args: List[str]) -> str:
        """Handle network info"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            addrs = psutil.net_if_addrs()
            
            response = "🌐 <b>Network Information</b>\n\n"
            response += f"Hostname: <code>{hostname}</code>\n"
            response += f"Local IP: <code>{local_ip}</code>\n\n"
            response += f"<b>Network Interfaces:</b>\n"
            
            for iface, addresses in list(addrs.items())[:5]:
                response += f"\n{iface}:\n"
                for addr in addresses[:2]:
                    response += f"  {addr.address}\n"
            
            return response
        except Exception as e:
            return f"❌ Error: {str(e)}"
    
    def handle_system_info(self, args: List[str]) -> str:
        """Handle system info"""
        response = "💻 <b>System Information</b>\n\n"
        response += f"OS: {platform.system()} {platform.release()}\n"
        response += f"CPU Cores: {psutil.cpu_count()}\n"
        response += f"CPU Usage: {psutil.cpu_percent()}%\n"
        response += f"Memory: {psutil.virtual_memory().percent}%\n"
        response += f"Disk: {psutil.disk_usage('/').percent}%\n"
        response += f"Boot Time: {datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M')}\n"
        return response
    
    def handle_threat_summary(self, args: List[str]) -> str:
        """Handle threat summary"""
        threats = self.monitor.db_manager.get_recent_threats(10)
        
        if not threats:
            return "✅ No recent threats detected"
        
        response = "🚨 <b>Recent Threats</b>\n\n"
        for ip, ttype, severity, ts in threats:
            response += f"• <code>{ip}</code>\n"
            response += f"  Type: {ttype} | Severity: {severity}\n"
            response += f"  Time: {ts}\n\n"
        
        return response
    
    def handle_generate_report(self, args: List[str]) -> str:
        """Handle generate report"""
        threats = self.monitor.db_manager.get_recent_threats(50)
        history = self.monitor.db_manager.get_command_history(100)
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'monitored_ips': len(self.monitor.monitored_ips),
            'total_threats': len(threats),
            'high_severity': len([t for t in threats if t[2] == 'high']),
            'medium_severity': len([t for t in threats if t[2] == 'medium']),
            'low_severity': len([t for t in threats if t[2] == 'low']),
            'commands_executed': len(history)
        }
        
        filename = f"report_{int(time.time())}.json"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        response = "📊 <b>Security Report</b>\n\n"
        response += f"Monitored IPs: {report['monitored_ips']}\n"
        response += f"Total Threats: {report['total_threats']}\n"
        response += f"High Severity: {report['high_severity']}\n"
        response += f"Medium Severity: {report['medium_severity']}\n"
        response += f"Low Severity: {report['low_severity']}\n"
        response += f"\n✅ Report saved: <code>{filename}</code>"
        
        return response
    
    def process_telegram_commands(self):
        """Process incoming Telegram commands"""
        if not self.monitor.telegram_token:
            return
            
        try:
            url = f"https://api.telegram.org/bot{self.monitor.telegram_token}/getUpdates"
            params = {'offset': self.last_update_id + 1, 'timeout': 10}
            response = requests.get(url, params=params, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if data['ok'] and 'result' in data:
                    for update in data['result']:
                        self.last_update_id = update['update_id']
                        if 'message' in update and 'text' in update['message']:
                            self.process_message(update['message'])
        except Exception as e:
            logging.error(f"Telegram error: {e}")
    
    def process_message(self, message):
        """Process individual message"""
        text = message['text']
        chat_id = message['chat']['id']
        
        if not self.monitor.telegram_chat_id:
            self.monitor.telegram_chat_id = str(chat_id)
            self.monitor.save_config()
        
        self.monitor.db_manager.log_command(text, 'telegram', True)
        
        parts = text.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        if command in self.command_handlers:
            try:
                def execute():
                    response = self.command_handlers[command](args)
                    self.send_telegram_message(response)
                
                thread = threading.Thread(target=execute, daemon=True)
                thread.start()
            except Exception as e:
                self.send_telegram_message(f"❌ Error: {str(e)}")
        else:
            self.send_telegram_message("❌ Unknown command. Type /help")

class CybersecurityMonitor:
    """Main monitor class"""
    
    def __init__(self):
        self.monitored_ips = set()
        self.monitoring_active = False
        self.telegram_token = None
        self.telegram_chat_id = None
        self.db_manager = DatabaseManager()
        self.scanner = NetworkScanner()
        self.traceroute_tool = TracerouteTool()
        self.setup_logging()
        self.load_config()
    
    def setup_logging(self):
        """Setup logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cybersecurity.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    def load_config(self):
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = set(config.get('monitored_ips', []))
        except Exception as e:
            logging.error(f"Config load error: {e}")
    
    def save_config(self):
        """Save configuration"""
        try:
            config = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Config save error: {e}")

def print_banner():
    """Print banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║          🛡️  ACCURATE ONLINE OS DEMO 🛡️               ║
    ║                                                       ║
    ║                                                       ║
    ║                                                       ║
    ║                                                       ║
    ║ Community:https://github.com/Accurate-Cyber-Defense   ║
    ║              Telegram Bot: ACTIVE                     ║
    ║              Database: Ready                          ║
    ║                                                       ║
    ║                                                       ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)

def setup_telegram():
    """Setup Telegram configuration"""
    print("\n🔧 Telegram Bot Setup")
    print("=" * 50)
    print("\nTo use Telegram commands:")
    print("1. Create a bot with @BotFather on Telegram")
    print("2. Get your bot token")
    print("3. Start chat with your bot and send /start")
    print("4. Get your chat ID\n")
    
    token = input("Enter Telegram bot token (or press Enter to skip): ").strip()
    if token:
        chat_id = input("Enter your chat ID: ").strip()
        return token, chat_id
    return None, None

def main():
    """Main function"""
    monitor = CybersecurityMonitor()
    telegram_handler = TelegramBotHandler(monitor)
    
    print_banner()
    
    # Setup Telegram if not configured
    if not monitor.telegram_token:
        token, chat_id = setup_telegram()
        if token and chat_id:
            monitor.telegram_token = token
            monitor.telegram_chat_id = chat_id
            monitor.save_config()
            print("✅ Telegram configured!")
        else:
            print("⚠️ Telegram features disabled")
    
    # Start Telegram command processor
    def telegram_processor():
        while True:
            try:
                telegram_handler.process_telegram_commands()
                time.sleep(2)
            except Exception as e:
                logging.error(f"Telegram error: {e}")
                time.sleep(10)
    
    telegram_thread = threading.Thread(target=telegram_processor, daemon=True)
    telegram_thread.start()
    
    if monitor.telegram_token and monitor.telegram_chat_id:
        print("✅ Telegram bot ACTIVE")
        print("📱 Send /start to your bot on Telegram")
        
        # Test connection
        test_msg = "🔗 <b>Accurate Online OS v2 - Connected!</b>\n\n✅ Bot is online\n🚀 Type /help for commands\n🛣️ Enhanced traceroute available!"
        telegram_handler.send_telegram_message(test_msg)
    
    print("\n💻 Local terminal commands available")
    print("📋 Type 'help' for command list\n")
    
    # Local command interface
    while True:
        try:
            command = input("accurateOS> ").strip()
            if not command:
                continue
            
            monitor.db_manager.log_command(command, 'local', True)
            
            parts = command.split()
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            if cmd == 'exit':
                print("👋 Exiting...")
                break
            
            elif cmd == 'help':
                print("""
Local Commands:
  ping [ip]              - Ping IP address
  tracert [ip]           - Traceroute (Windows)
  traceroute [ip]        - Traceroute (Linux/Mac)
  advanced_traceroute [ip] - Enhanced traceroute
  scan [ip]              - Port scan
  location [ip]          - Get IP location
  analyze [ip]           - Analyze IP
  whois [domain]         - WHOIS lookup
  dns [domain]           - DNS lookup
  
  start_monitoring [ip]  - Start monitoring IP
  add [ip]               - Add IP to monitoring
  remove [ip]            - Remove IP
  list                   - List monitored IPs
  stop                   - Stop monitoring
  
  network_info           - Network information
  system_info            - System information
  status                 - System status
  history                - Command history
  threats                - Threat summary
  report                 - Generate report
  
  config                 - Configure Telegram
  clear                  - Clear screen
  exit                   - Exit program

All commands also available via Telegram!
                """)
            
            elif cmd == 'ping' and args:
                result = monitor.scanner.ping_ip(args[0])
                print(result)
            
            elif cmd in ['tracert', 'traceroute'] and args:
                print(f"Traceroute to {args[0]}...")
                result = monitor.scanner.traceroute(args[0])
                print(result)
            
            elif cmd == 'advanced_traceroute' and args:
                print(f"🚀 Advanced traceroute to {args[0]}...")
                result = monitor.traceroute_tool.interactive_traceroute(args[0])
                print(result)
            
            elif cmd == 'scan' and args:
                print(f"Scanning {args[0]}...")
                result = monitor.scanner.port_scan(args[0])
                if result['success']:
                    print(f"\n📊 Scan Results for {args[0]}:")
                    open_ports = result.get('open_ports', [])
                    print(f"Open Ports: {len(open_ports)}\n")
                    for p in open_ports:
                        print(f"  Port {p['port']}: {p['service']}")
                else:
                    print(f"❌ Error: {result.get('error', 'Unknown')}")
            
            elif cmd == 'location' and args:
                result = monitor.scanner.get_ip_location(args[0])
                print(result)
            
            elif cmd == 'analyze' and args:
                ip = args[0]
                print(f"\n🔍 Analyzing {ip}...\n")
                
                # Location
                location = monitor.scanner.get_ip_location(ip)
                try:
                    loc_data = json.loads(location)
                    print(f"📍 Location: {loc_data.get('city', 'N/A')}, {loc_data.get('country', 'N/A')}")
                    print(f"🏢 ISP: {loc_data.get('isp', 'N/A')}\n")
                except:
                    pass
                
                # Threats
                threats = monitor.db_manager.get_recent_threats(10)
                ip_threats = [t for t in threats if t[0] == ip]
                
                if ip_threats:
                    print(f"🚨 Threats Found: {len(ip_threats)}")
                    for threat in ip_threats:
                        print(f"  • {threat[1]}: {threat[2]}")
                else:
                    print("✅ No recent threats detected")
            
            elif cmd == 'whois' and args:
                try:
                    result = subprocess.run(['whois', args[0]], capture_output=True, text=True, timeout=30)
                    print(result.stdout)
                except:
                    print("❌ WHOIS lookup failed")
            
            elif cmd == 'dns' and args:
                try:
                    ip = socket.gethostbyname(args[0])
                    print(f"🌐 {args[0]} → {ip}")
                except Exception as e:
                    print(f"❌ DNS lookup failed: {e}")
            
            elif cmd == 'start_monitoring' and args:
                ip = args[0]
                try:
                    ipaddress.ip_address(ip)
                    monitor.monitored_ips.add(ip)
                    monitor.save_config()
                    print(f"✅ Started monitoring {ip}")
                except ValueError:
                    print(f"❌ Invalid IP: {ip}")
            
            elif cmd == 'add' and args:
                ip = args[0]
                try:
                    ipaddress.ip_address(ip)
                    monitor.monitored_ips.add(ip)
                    monitor.save_config()
                    print(f"✅ Added {ip}")
                except ValueError:
                    print(f"❌ Invalid IP: {ip}")
            
            elif cmd == 'remove' and args:
                ip = args[0]
                if ip in monitor.monitored_ips:
                    monitor.monitored_ips.remove(ip)
                    monitor.save_config()
                    print(f"✅ Removed {ip}")
                else:
                    print(f"❌ IP not in list: {ip}")
            
            elif cmd == 'list':
                if monitor.monitored_ips:
                    print("\n📋 Monitored IPs:")
                    for ip in sorted(monitor.monitored_ips):
                        print(f"  • {ip}")
                else:
                    print("📋 No IPs are being monitored")
            
            elif cmd == 'stop':
                if monitor.monitored_ips:
                    ips = list(monitor.monitored_ips)
                    monitor.monitored_ips.clear()
                    monitor.save_config()
                    print(f"🛑 Stopped monitoring: {', '.join(ips)}")
                else:
                    print("⚠️ No IPs are being monitored")
            
            elif cmd == 'network_info':
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                print(f"\n🌐 Network Information:")
                print(f"  Hostname: {hostname}")
                print(f"  Local IP: {local_ip}")
                print(f"  Connections: {len(psutil.net_connections())}")
            
            elif cmd == 'system_info':
                print(f"\n💻 System Information:")
                print(f"  OS: {platform.system()} {platform.release()}")
                print(f"  CPU Cores: {psutil.cpu_count()}")
                print(f"  CPU Usage: {psutil.cpu_percent()}%")
                print(f"  Memory: {psutil.virtual_memory().percent}%")
                print(f"  Disk: {psutil.disk_usage('/').percent}%")
            
            elif cmd == 'status':
                cpu = psutil.cpu_percent(interval=1)
                mem = psutil.virtual_memory()
                print(f"\n📊 System Status:")
                print(f"  Bot: {'Online' if monitor.telegram_token else 'Offline'}")
                print(f"  Monitored IPs: {len(monitor.monitored_ips)}")
                print(f"  CPU: {cpu}%")
                print(f"  Memory: {mem.percent}%")
                print(f"  Connections: {len(psutil.net_connections())}")
            
            elif cmd == 'history':
                history = monitor.db_manager.get_command_history(20)
                if history:
                    print("\n📜 Command History:")
                    for cmd, src, ts, success in history:
                        status = "✅" if success else "❌"
                        print(f"  {status} [{src}] {cmd} | {ts}")
                else:
                    print("📜 No commands recorded")
            
            elif cmd == 'threats':
                threats = monitor.db_manager.get_recent_threats(10)
                if threats:
                    print("\n🚨 Recent Threats:")
                    for ip, ttype, severity, ts in threats:
                        print(f"  • {ip}")
                        print(f"    Type: {ttype} | Severity: {severity}")
                        print(f"    Time: {ts}\n")
                else:
                    print("✅ No recent threats detected")
            
            elif cmd == 'report':
                threats = monitor.db_manager.get_recent_threats(50)
                history = monitor.db_manager.get_command_history(100)
                
                report = {
                    'generated_at': datetime.now().isoformat(),
                    'monitored_ips': len(monitor.monitored_ips),
                    'total_threats': len(threats),
                    'high_severity': len([t for t in threats if t[2] == 'high']),
                    'medium_severity': len([t for t in threats if t[2] == 'medium']),
                    'low_severity': len([t for t in threats if t[2] == 'low']),
                    'commands_executed': len(history)
                }
                
                filename = f"report_{int(time.time())}.json"
                os.makedirs(REPORT_DIR, exist_ok=True)
                filepath = os.path.join(REPORT_DIR, filename)
                
                with open(filepath, 'w') as f:
                    json.dump(report, f, indent=2)
                
                print(f"\n📊 Security Report:")
                print(f"  Monitored IPs: {report['monitored_ips']}")
                print(f"  Total Threats: {report['total_threats']}")
                print(f"  High Severity: {report['high_severity']}")
                print(f"  Medium Severity: {report['medium_severity']}")
                print(f"  Low Severity: {report['low_severity']}")
                print(f"\n✅ Report saved: {filename}")
            
            elif cmd == 'config':
                token, chat_id = setup_telegram()
                if token and chat_id:
                    monitor.telegram_token = token
                    monitor.telegram_chat_id = chat_id
                    monitor.save_config()
                    print("✅ Telegram configured!")
            
            elif cmd == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            
            else:
                print("Unknown command. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print("\n👋 Exiting...")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            monitor.db_manager.log_command(command, 'local', False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Thank you for using Accurate Online OS Demo!")
    except Exception as e:
        print(f"❌ Application error: {e}")
        logging.exception("Application crash")