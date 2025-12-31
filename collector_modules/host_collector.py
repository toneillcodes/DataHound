import os
import socket
import uuid
import json
import logging
import getpass
import platform
import psutil
import subprocess
import pandas as pd
from pathlib import Path

def collect_windows_host_enumeration(config):
    """
    Collects comprehensive host metadata, multi-interface IP mapping,
    VPN/Proxy detection, account details, memory stats, and drive info.
    """
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))
    results = []

    try:
        host_info = {
            "correlation_id": correlation_id,
            "type": "HOST_ENUMERATION_EXTENDED",
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(), # Added: Fully Qualified Domain Name
            "os_platform": platform.system(),
            "os_version": platform.version(),
            "os_release": platform.release(), # Added: e.g., "10" or "11"
            "architecture": platform.machine(), # Added: e.g., "AMD64"
            "current_user": getpass.getuser(),
        }

        # 1. Memory Statistics (RAM)
        try:
            mem = psutil.virtual_memory()
            host_info["ram_total_gb"] = round(mem.total / (1024**3), 2)
            host_info["ram_available_gb"] = round(mem.available / (1024**3), 2)
            host_info["ram_usage_percent"] = mem.percent
        except Exception as e:
            logging.warning(f"Memory collection failed: {e}")

        # 2. Drive & Partition Enumeration
        try:
            drive_data = []
            partitions = psutil.disk_partitions()
            for p in partitions:
                drive_info = {"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype}
                try:
                    usage = psutil.disk_usage(p.mountpoint)
                    drive_info["total_gb"] = round(usage.total / (1024**3), 2)
                    drive_info["used_percent"] = usage.percent
                except PermissionError:
                    # Occurs on CD-ROMs or locked system drives
                    drive_info["total_gb"] = "Locked/Empty"
                drive_data.append(drive_info)
            host_info["drive_summary"] = json.dumps(drive_data)
        except Exception as e:
            logging.warning(f"Drive collection failed: {e}")

        # 3. Local Interface Resolution & VPN Detection
        all_interfaces = {}
        flags = []
        try:
            if_addrs = psutil.net_if_addrs()
            for iface_name, snics in if_addrs.items():
                ips = [snic.address for snic in snics if snic.family == socket.AF_INET]
                if ips:
                    all_interfaces[iface_name] = ips
                    lower_name = iface_name.lower()
                    if any(term in lower_name for term in ['tun', 'tap', 'vpn', 'ppp']):
                        flags.append(f"Active_VPN_Interface:{iface_name}")
                    if any(term in lower_name for term in ['vbox', 'vmware', 'docker', 'veth']):
                        flags.append(f"Virtual_Interface:{iface_name}")

            host_info["all_local_ips"] = json.dumps(all_interfaces)
            host_info["network_flags"] = ", ".join(flags) if flags else "None"
        except Exception as e:
            logging.warning(f"Interface enum failed: {str(e)}")

        # 4. Proxy & Domain Information
        if platform.system() == "Windows":
            try:
                reg_cmd = 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v ProxyEnable'
                proxy_check = subprocess.run(reg_cmd, capture_output=True, text=True, shell=True)
                host_info["proxy_enabled"] = "1" in proxy_check.stdout
                
                domain_cmd = subprocess.run(["wmic", "computersystem", "get", "partofdomain"], capture_output=True, text=True)
                host_info["is_domain_joined"] = "TRUE" in domain_cmd.stdout.upper()
            except Exception:
                host_info["proxy_enabled"] = "Unknown"

        # 5. Detailed Account Enumeration
        try:
            # Get currently logged-in users
            host_info["active_sessions"] = ", ".join(list(set(u.name for u in psutil.users())))
            
            accounts = []
            home_dirs = []

            if platform.system() == "Windows":
                # 1. Enumerate via Net User
                acc_cmd = subprocess.run(["net", "user"], capture_output=True, text=True)
                lines = acc_cmd.stdout.splitlines()
                for line in lines[4:]: 
                    if "The command completed" in line: break
                    accounts.extend([name.strip() for name in line.split() if name.strip()])
                
                # 2. Review Users Directory
                user_path = "C:\\Users"
                if os.path.exists(user_path):
                    # Filter out system defaults like 'Public' or 'Default'
                    ignored = ['Public', 'Default', 'Default User', 'All Users', 'desktop.ini']
                    home_dirs = [d for d in os.listdir(user_path) if d not in ignored and os.path.isdir(os.path.join(user_path, d))]

            host_info["total_local_accounts"] = ", ".join(accounts)
            host_info["filesystem_user_dirs"] = ", ".join(home_dirs)
            
            # Identify discrepancies (Dirs found on disk but not in 'net user')
            ghost_accounts = list(set(home_dirs) - set(accounts))
            host_info["potential_ghost_accounts"] = ", ".join(ghost_accounts) if ghost_accounts else "None"

        except Exception as e:
            host_info["total_local_accounts"] = f"Error enumerating: {str(e)}"

        results.append(host_info)
        return pd.DataFrame(results)

    except Exception as e:
        logging.error(json.dumps({"event": "COLLECT_ERROR", "error": str(e)}))
        return None

def collect_linux_host_enumeration(config):
    """
    Collects comprehensive Linux host metadata, including network flags, 
    proxy environments, and account/privilege details.
    """
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))
    results = []

    try:
        host_info = {
            "correlation_id": correlation_id,
            "type": "HOST_ENUMERATION_LINUX",
            "hostname": socket.gethostname(),
            "os_platform": platform.system(),
            "os_kernel": platform.release(),
            "current_user": getpass.getuser(),
            "uid": os.getuid() if hasattr(os, 'getuid') else "N/A"
        }

        # 1. Primary Outbound IP Discovery (Same logic as Windows)
        '''
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(('1.1.1.1', 1))
            host_info["primary_outbound_ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            host_info["primary_outbound_ip"] = "Disconnected"
        '''

        # 2. Linux Network Interface & VPN Detection
        all_interfaces = {}
        flags = []
        try:
            if_addrs = psutil.net_if_addrs()
            for iface_name, snics in if_addrs.items():
                ips = [snic.address for snic in snics if snic.family == socket.AF_INET]
                if ips:
                    all_interfaces[iface_name] = ips
                    lower_name = iface_name.lower()
                    if any(term in lower_name for term in ['tun', 'tap', 'vpn', 'wg', 'ppp']):
                        flags.append(f"Active_VPN_Interface:{iface_name}")
                    if any(term in lower_name for term in ['docker', 'veth', 'br-', 'virbr']):
                        flags.append(f"Container_Virtual_Interface:{iface_name}")

            host_info["all_local_ips"] = json.dumps(all_interfaces)
            host_info["network_flags"] = ", ".join(flags) if flags else "None"
        except Exception as e:
            logging.warning(f"Interface enum failed: {str(e)}")

        # 3. Linux Proxy & Environment Detection
        # In Linux, proxies are usually defined in env vars rather than registry
        try:
            proxy_vars = {k: v for k, v in os.environ.items() if "proxy" in k.lower()}
            host_info["proxy_enabled"] = len(proxy_vars) > 0
            host_info["proxy_details"] = json.dumps(proxy_vars)
            
            # Check for Domain membership via realm or sssd
            domain_check = subprocess.run(["realm", "list"], capture_output=True, text=True)
            host_info["is_domain_joined"] = len(domain_check.stdout.strip()) > 0
        except Exception:
            host_info["proxy_enabled"] = False

        # 4. Linux Account & Privilege Enumeration
        try:
            # Active SSH/Tty sessions
            host_info["active_sessions"] = ", ".join(list(set(u.name for u in psutil.users())))
            
            # List all accounts with a login shell (UID >= 1000 or root)
            accounts = []
            with open("/etc/passwd", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 2:
                        user = parts[0]
                        uid = int(parts[2])
                        if uid == 0 or uid >= 1000:
                            accounts.append(user)
            host_info["total_local_accounts"] = ", ".join(accounts)
            
            # Sudo capability check (non-blocking)
            sudo_check = subprocess.run(["sudo", "-n", "-l"], capture_output=True, text=True)
            host_info["has_sudo_access"] = sudo_check.returncode == 0
        except Exception:
            host_info["total_local_accounts"] = "Error"

        results.append(host_info)

        logging.info(json.dumps({
            "event": "LINUX_HOST_ENUM_COMPLETE",
            "correlation_id": correlation_id,
            "is_root": host_info["uid"] == 0
        }))

        return pd.DataFrame(results)

    except Exception as e:
        logging.error(json.dumps({
            "event": "COLLECT_ERROR",
            "correlation_id": correlation_id,
            "error": str(e)
        }))
        return None    