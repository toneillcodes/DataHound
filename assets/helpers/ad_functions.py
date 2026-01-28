import socket
import platform
from ldap3 import Server, Connection, ALL, SUBTREE

# Global flag to check environment
IS_WINDOWS = platform.system() == "Windows"

def get_local_sid_via_wmi(ip_address, username, password):
    """
    Retrieves the machine SID directly from the target via WMI.
    Only works if running FROM a Windows machine.
    """
    if not IS_WINDOWS:
        return "Error: WMI lookups require the script to run on a Windows host."

    try:
        # Import inside the function so Linux doesn't crash on module load
        import wmi
        
        # Initialize connection
        conn = wmi.WMI(ip_address, user=username, password=password)
        
        # Query local accounts to extract the Machine SID
        for account in conn.Win32_UserAccount(LocalAccount=True):
            full_sid = account.SID
            machine_sid = "-".join(full_sid.split("-")[:-1])
            return {
                "hostname": account.Domain,
                "machine_sid": machine_sid,
                "method": "WMI"
            }
            
    except Exception as e:
        return f"Error connecting to {ip_address} via WMI: {e}"


def get_sid_from_ip_ldap(ip_address, ldap_server, user_dn, password, search_base):
    """
    Resolves IP to Hostname via DNS, then Hostname to SID via LDAP.
    Works on both Windows and Linux.
    """
    try:
        # 1. Reverse DNS Lookup
        hostname_data = socket.gethostbyaddr(ip_address)
        hostname = hostname_data[0].split('.')[0] 
        
        # 2. LDAP Search
        server = Server(ldap_server, get_info=ALL)
        with Connection(server, user=user_dn, password=password, auto_bind=True) as conn:
            search_filter = f"(&(objectClass=computer)(sAMAccountName={hostname}$))"
            conn.search(search_base, search_filter, attributes=['objectSid'])
            
            if conn.entries:
                return {
                    "hostname": hostname,
                    "sid": str(conn.entries[0].objectSid),
                    "method": "LDAP"
                }
            return f"Error: Computer {hostname} not found in AD."
                
    except socket.herror:
        return f"Error: Reverse DNS lookup failed for {ip_address}."
    except Exception as e:
        return f"Unexpected LDAP error: {e}"