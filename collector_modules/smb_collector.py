import os
import json
import logging
import uuid
import platform
import subprocess
import pandas as pd

def collect_smb_share_enumeration(config):
    """
    Specifically enumerates mapped network drives and active SMB connections.
    Returns a DataFrame of discovered remote paths.
    """
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))
    results = []
    system_type = platform.system()

    try:
        if system_type == "Windows":
            # Using 'net use' to find mapped letters (Z:, Y:, etc.)
            # and 'wmic' for a more robust list of network connections
            commands = [
                ["net", "use"],
                ["wmic", "netuse", "get", "LocalName,RemotePath", "/format:csv"]
            ]
            
            for cmd in commands:
                proc = subprocess.run(cmd, capture_output=True, text=True, shell=True)
                if proc.returncode == 0:
                    results.append({
                        "correlation_id": correlation_id,
                        "type": "SMB_ENUMERATION",
                        "method": " ".join(cmd),
                        "raw_output": proc.stdout.strip(),
                        "status": "SUCCESS"
                    })

        elif system_type == "Linux" or system_type == "Darwin":
            # Check /proc/mounts or 'mount' command for cifs/smbfs
            try:
                with open('/proc/mounts', 'r') as f:
                    smb_mounts = [line.strip() for line in f if 'cifs' in line or 'smb' in line]
                    if smb_mounts:
                        results.append({
                            "correlation_id": correlation_id,
                            "type": "SMB_ENUMERATION",
                            "method": "read_proc_mounts",
                            "raw_output": "|".join(smb_mounts),
                            "status": "SUCCESS"
                        })
            except FileNotFoundError:
                # Fallback for macOS (Darwin)
                proc = subprocess.run(["mount"], capture_output=True, text=True)
                results.append({
                    "correlation_id": correlation_id,
                    "type": "SMB_ENUMERATION",
                    "method": "mount_cmd",
                    "raw_output": proc.stdout.strip(),
                    "status": "SUCCESS"
                })

        if not results:
            logging.info(json.dumps({
                "event": "SMB_ENUM_EMPTY",
                "correlation_id": correlation_id,
                "message": "No active SMB shares or mapped drives found."
            }))
            return pd.DataFrame()

        logging.info(json.dumps({
            "event": "SMB_ENUM_COMPLETE",
            "correlation_id": correlation_id,
            "shares_found": len(results)
        }))

        return pd.DataFrame(results)

    except Exception as e:
        logging.error(json.dumps({
            "event": "SMB_COLLECT_ERROR",
            "correlation_id": correlation_id,
            "error": str(e)
        }))
        return None