import os
import uuid
import json
import struct
import binascii
import logging
import platform
import pandas as pd
from datetime import datetime

# Import win32 libraries for SID resolution
try:
    import win32security
except ImportError:
    print("[!] Please install pywin32: pip install pywin32")

from pathlib import Path
from collector_modules.host_collector import collect_windows_host_enumeration

"""
Ported from PowerDPAPI @ https://github.com/toneillcodes/PowerDPAPI
Original PoC and DPAPI research @ https://github.com/toneillcodes/dpapi-projects
"""

def collect_dpapi_blob_data(config):
    """
    Scans a directory for DPAPI blobs. 
    Returns a list of dicts containing blob metadata and MasterKey GUIDs.
    """
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))
    source_path = config.get('source_path')
    
    if not source_path or not os.path.exists(source_path):
        logging.error(json.dumps({
            "event": "CONFIG_ERROR",
            "correlation_id": correlation_id,
            "message": f"'source_path' is invalid or missing: {source_path}"
        }))
        return None
    
    # DPAPI Magic Header
    DPAPI_MAGIC = binascii.unhexlify("01000000D08C9DDF0115D1118C7A00C04FC297EB")
    results = []

    try:
        for file_path in Path(source_path).rglob('*'):
            if not file_path.is_file():
                continue
            
            try:
                with open(file_path, 'rb') as f:
                    # todo: add a configuration property to control this
                    bytes_to_read = config.get('bytes_to_read', 1024)
                    header = f.read(bytes_to_read)
                
                '''
                Offset (from Magic),Size,Description
                0,20 bytes,DPAPI_MAGIC
                20,4 bytes,Version
                24,16 bytes,Provider GUID (MasterKey GUID)
                40,4 bytes,MasterKey Version
                44,4 bytes,Description Length (in bytes)
                48,len bytes,Description (UTF-16LE String)
                '''

                magic_idx = header.find(DPAPI_MAGIC)
                if magic_idx != -1:
                    # Offset to MasterKey GUID: Magic(20) + Version(4) + Provider(16) + MKVersion(4)
                    # Note: magic_idx is start of header, skip 24 bytes to reach GUID
                    ptr = magic_idx + 24 
                    file_bytes = file_path.read_bytes()
                    
                    mk_guid_bytes = file_bytes[ptr:ptr+16]
                    mk_guid = str(uuid.UUID(bytes_le=mk_guid_bytes))

                    # 2. Extract Description
                    # Description Length is 4 bytes, located after the MasterKey GUID
                    desc_len_ptr = ptr + 20 # Skip GUID (16) and MK Version (4)
                    desc_len = struct.unpack("<I", file_bytes[desc_len_ptr:desc_len_ptr+4])[0]
                    
                    description = ""
                    if desc_len > 0:
                        desc_ptr = desc_len_ptr + 4
                        desc_bytes = file_bytes[desc_ptr : desc_ptr + desc_len]
                        # DPAPI strings are UTF-16LE. We strip null terminators.
                        description = desc_bytes.decode('utf-16le').strip('\x00')                   

                    # todo: add file modification timestamp
                    results.append({
                        "correlation_id": correlation_id,
                        "file_path": str(file_path),
                        "file_name": file_path.name,
                        "master_key_guid": mk_guid,
                        "description": description,                        
                        "type": "DPAPI_BLOB"
                    })
                    
                    logging.info(json.dumps({
                        "event": "DPAPI_BLOB_FOUND",
                        "correlation_id": correlation_id,
                        "file": str(file_path),
                        "mk_guid": mk_guid
                    }))
            except Exception as e:
                continue # Skip files we can't read

        # after all that, the results array is still empty
        if not results:
            return None

        # convert the blob data to a dataframe
        df_blob = pd.DataFrame(results)
        
        # do we need to merge the computer information to the dataframe?
        # check if we have any computer information in the df_host dataframe        
        df_host = None
        if config.get('collect_computer_info', 'False'):
            df_host = collect_windows_host_enumeration(config)
            if df_host is None:
                logging.error("Failed to retrieve Computer information as part of the DPAPI collection. Skipping.")
        # did the host dataframe get populated? if not return df_blob
        if df_host is None:                
            return df_blob
        else:
            # if the host df was populated, merge with df_blob and return the result
            merged_df = pd.merge(df_blob, df_host, how="cross")
            return merged_df

    except Exception as e:
        logging.error(json.dumps({
            "event": "COLLECT_ERROR",
            "correlation_id": correlation_id,
            "error": str(e)
        }))
        return None 

def resolve_sid(sid_string):
    """
    Converts a SID string (S-1-5-21...) into a Username.
    param sid_string: The SID to convert
    """
    try:
        sid = win32security.GetBinarySid(sid_string)
        name, domain, type = win32security.LookupAccountSid(None, sid)
        return f"{domain}\\{name}"
    except Exception:
        return "Unknown or Deleted Account"

def collect_masterkey_data(guid):
    if platform.system() != "Windows":
        return []

    guid = guid.strip("{}").lower()
    search_paths = [
        os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Protect'),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'Microsoft', 'Protect')
    ]
    
    results = []

    for root_path in search_paths:
        if not os.path.exists(root_path):
            continue
            
        path_obj = Path(root_path)
        for path in path_obj.rglob(guid):
            if path.is_file():
                try:
                    owner_sid = path.parent.name
                    username = resolve_sid(owner_sid) # Resolve the SID here
                    
                    stat = path.stat()
                    with open(path, "rb") as f:
                        header = f.read(24)
                        
                    version = struct.unpack("<L", header[0:4])[0]
                    salt = header[4:20].hex()
                    iterations = struct.unpack("<L", header[20:24])[0]

                    # todo: add file modification timestamp
                    results.append({
                        "GUID": guid,
                        "Username": username,
                        "Owner_SID": owner_sid,
                        "Version": version,
                        "Iterations": iterations,
                        "Salt_Hex": salt,
                        "Created_At": datetime.fromtimestamp(stat.st_ctime),
                        "Full_Path": str(path)
                    })
                except Exception:
                    continue

    return results