from typing import Optional
import pandas as pd
import logging
import json
import uuid
import xml.etree.ElementTree as ET

from collector_modules.xml_collector import collect_xml_data

def process_nmap_xml(xml_path):
    """
    Coordinator that uses collect_xml_data to parse Nmap results.
    Flattens host and port information into a security-focused DataFrame.
    """
    # Generate the shared correlation_id for this session
    session_correlation_id = str(uuid.uuid4())
    
    # Configuration for your XML collector
    # We target './/host' to get one row per host found in the scan
    config = {
        "input_file": xml_path,
        "data_root": ".//host",
        "correlation_id": session_correlation_id
    }

    # 1. Use your collector to get the base host data
    df_hosts = collect_xml_data(config)
    
    if df_hosts is None:
        return None

    # 2. Extract Interesting Data (Post-Processing)
    # Since Nmap XML is complex, pandas read_xml puts nested tags in specific columns.
    # We refine the dataframe to focus on: IP, Status, Port, Service
    
    refined_rows = []
    
    # We iterate through the raw XML again or use the DF if it captured nested objects
    # For Nmap, it's often more reliable to parse the 'ports' sub-nodes
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for host in root.findall(".//host"):
        # Get IP Address
        addr_tag = host.find("./address[@addrtype='ipv4']")
        ip = addr_tag.get('addr') if addr_tag is not None else "unknown"
        
        # Get Status
        status_tag = host.find("./status")
        state = status_tag.get('state') if status_tag is not None else "unknown"

        # Get Ports
        for port in host.findall(".//port"):
            port_id = port.get('portid')
            protocol = port.get('protocol')
            
            state_tag = port.find("./state")
            port_state = state_tag.get('state') if state_tag is not None else "unknown"
            
            service_tag = port.find("./service")
            service_name = service_tag.get('name') if service_tag is not None else "unknown"

            refined_rows.append({
                "correlation_id": session_correlation_id,
                "ip_address": ip,
                "host_state": state,
                "port": port_id,
                "protocol": protocol,
                "port_state": port_state,
                "service": service_name
            })

    return pd.DataFrame(refined_rows)

def collect_nmap_hosts_xml(xml_path, config=None):
    """
    Parses Nmap XML to return a DataFrame of hosts and their up/down status.
    One row per unique IP address.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    host_data = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall(".//host"):
            # Extract IP (preferring IPv4)
            addr_tag = host.find("./address[@addrtype='ipv4']")
            ip = addr_tag.get('addr') if addr_tag is not None else "unknown"
            
            # Extract Hostname (if available)
            name_tag = host.find(".//hostname")
            hostname = name_tag.get('name') if name_tag is not None else "<unknown>"

            # Extract Status
            status_tag = host.find("./status")
            state = status_tag.get('state') if status_tag is not None else "unknown"

            host_data.append({
                "correlation_id": correlation_id,
                "ip_address": ip,
                "hostname": hostname,
                "host_status": state,
                "type": "HOST_STATUS"
            })

        return pd.DataFrame(host_data)

    except Exception as e:
        logging.error(json.dumps({"event": "HOST_STATUS_PARSE_ERROR", "error": str(e)}))
        return pd.DataFrame()
    
def collect_nmap_ports_xml(xml_path, config=None):
    """
    Parses Nmap XML to return a DataFrame focusing on port and service status.
    One row per port found on each host.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    port_rows = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall(".//host"):
            addr_tag = host.find("./address[@addrtype='ipv4']")
            ip = addr_tag.get('addr') if addr_tag is not None else "<unknown>"
            
            # Only process ports if the host is up, otherwise Nmap may not have data
            for port in host.findall(".//port"):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                
                state_tag = port.find("./state")
                port_state = state_tag.get('state') if state_tag is not None else "unknown"
                
                service_tag = port.find("./service")
                service_name = service_tag.get('name') if service_tag is not None else "unknown"
                product = service_tag.get('product') if service_tag is not None else ""

                # combine port with the IP to generate a fake GUID to prevent node collisons
                # does this really matter? maybe not. it might be interesting to have common port nodes...idk
                # maintaining a familiar format will make it easy to parse visually
                fake_guid = f"{ip}:{port_id}"

                port_rows.append({
                    "correlation_id": correlation_id,
                    "port_guid": fake_guid,
                    "ip_address": ip,
                    "port": port_id,
                    "protocol": protocol,
                    "port_state": port_state,
                    "service_name": service_name,
                    "version": product,
                    "type": "PORT_DETAIL"
                })

        return pd.DataFrame(port_rows)

    except Exception as e:
        logging.error(json.dumps({"event": "PORT_DETAIL_PARSE_ERROR", "error": str(e)}))
        return pd.DataFrame()

def collect_merged_nmap_report(xml_path, config=None):
    """
    Merges host status and port details into a single flattened DataFrame.
    Each row represents a unique Port-on-Host instance.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    
    # 1. Collect the individual DataFrames using our existing methods
    df_hosts = collect_nmap_hosts_xml(xml_path, config)
    df_ports = collect_nmap_ports_xml(xml_path, config)

    if df_hosts.empty:
        logging.warning(json.dumps({
            "event": "MERGE_FAILED",
            "correlation_id": correlation_id,
            "message": "No host data found in XML"
        }))
        return pd.DataFrame()

    # 2. Perform the Merge
    # We join on ip_address. If a host has no ports, it will show NaN for port columns.
    merged_df = pd.merge(
        df_ports, 
        df_hosts[['ip_address', 'hostname', 'host_status']], 
        on='ip_address', 
        how='left'
    )

    # 3. Clean up and Reorder for Security Analysis
    column_order = [
        'correlation_id', 'ip_address', 'hostname', 'host_status', 
        'port', 'protocol', 'port_state', 'service_name', 'version'
    ]
    
    # Ensure all columns exist before reordering (in case of empty port scans)
    existing_cols = [c for c in column_order if c in merged_df.columns]
    merged_df = merged_df[existing_cols]

    logging.info(json.dumps({
        "event": "NMAP_MERGE_COMPLETE",
        "correlation_id": correlation_id,
        "total_records": len(merged_df),
        "unique_hosts": merged_df['ip_address'].nunique()
    }))

    return merged_df