import xml.etree.ElementTree as ET
from typing import Optional
import pandas as pd
import logging
import json
import uuid
import re
import ipaddress

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

import ipaddress
import xml.etree.ElementTree as ET

def collect_nmap_subnets_xml(xml_path, subnet_mask='/24', config=None):
    """
    Identifies all unique networks found in the Nmap XML results.
    Useful for high-level network segmentation reporting.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    networks = set()

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall(".//host"):
            addr_tag = host.find("./address[@addrtype='ipv4']")
            if addr_tag is not None:
                ip_str = addr_tag.get('addr')
                # Calculate network address (e.g., 192.168.1.0/24)
                interface = ipaddress.IPv4Interface(f"{ip_str}{subnet_mask}")
                networks.add(str(interface.network))

        subnet_data = [{
            "correlation_id": correlation_id,
            "subnet": net,
            "type": "SUBNET_IDENTIFIED"
        } for net in networks]

        return pd.DataFrame(subnet_data)

    except Exception as e:
        logging.error(json.dumps({"event": "XML_SUBNET_PARSE_ERROR", "error": str(e)}))
        return pd.DataFrame()

def collect_nmap_subnet_members_xml(xml_path, subnet_mask='/24', config=None):
    """
    Returns a mapping of Subnets to Hosts from Nmap XML.
    One row per Host, enriched with its parent Subnet details.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    
    # Use your existing host collector to get the base data
    df_hosts = collect_nmap_hosts_xml(xml_path, config)
    
    if df_hosts.empty:
        return pd.DataFrame()

    mapping_rows = []
    
    for _, row in df_hosts.iterrows():
        ip_str = row['ip_address']
        if ip_str == "unknown":
            continue
            
        try:
            # Create interface to derive the network
            interface = ipaddress.IPv4Interface(f"{ip_str}{subnet_mask}")
            
            mapping_rows.append({
                "correlation_id": correlation_id,
                "subnet": str(interface.network),
                "ip_address": ip_str,
                "hostname": row.get('hostname', '<unknown>'),
                "host_status": row.get('host_status', 'unknown'),
                "type": "SUBNET_HOST_MAP"
            })
        except ValueError as e:
            logging.warning(json.dumps({"event": "INVALID_IP_ENCOUNTERED", "ip": ip_str, "error": str(e)}))
            continue

    return pd.DataFrame(mapping_rows)        

def collect_full_security_manifest(xml_path, subnet_mask='/24'):
    config = {"correlation_id": str(uuid.uuid4())}
    
    df_merged = collect_merged_nmap_report(xml_path, config)
    df_subnets = collect_nmap_subnet_members_xml(xml_path, subnet_mask, config)
    
    if df_subnets.empty:
        return df_merged

    # Merge subnet info into the port-level data
    return pd.merge(
        df_merged, 
        df_subnets[['ip_address', 'subnet']], 
        on='ip_address', 
        how='left'
    )

def collect_complete_nmap_manifest_xml(xml_path, subnet_mask='/24', config=None):
    """
    The ultimate merge: Subnet -> Host -> Port.
    Each row represents a port, enriched with both Host and Subnet metadata.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    config = {"correlation_id": correlation_id}

    # 1. Collect Port/Service data
    df_main = collect_merged_nmap_report(xml_path, config)
    
    # 2. Collect Subnet Mapping
    df_subnets = collect_nmap_subnet_members_xml(xml_path, subnet_mask, config)

    if df_main.empty or df_subnets.empty:
        return df_main

    # 3. Final Merge
    # We bring in the 'subnet' column based on ip_address
    manifest_df = pd.merge(
        df_main,
        df_subnets[['ip_address', 'subnet']],
        on='ip_address',
        how='left'
    )

    # Reorder to put Subnet near the front for better visibility
    cols = ['correlation_id', 'subnet', 'ip_address', 'hostname', 'host_status', 
            'port', 'protocol', 'port_state', 'service_name', 'version']
    
    return manifest_df[cols]

def process_nmap_gnmap(gnmap_path):
    """
    Coordinator that parses GNMAP results.
    Flattens host and port information into a security-focused DataFrame.
    """
    session_correlation_id = str(uuid.uuid4())
    config = {"correlation_id": session_correlation_id}

    # In GNMAP, we don't have a 'data_root' like XML, 
    # so we call our merged collector directly.
    df = collect_merged_nmap_report_gnmap(gnmap_path, config)
    
    return df

def collect_nmap_hosts_gnmap(gnmap_path, config=None):
    """
    Parses Nmap GNMAP to return a DataFrame of hosts.
    One row per unique IP address.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    host_data = []

    try:
        with open(gnmap_path, 'r') as f:
            for line in f:
                # Ignore comments and headers
                if line.startswith('#') or "Status:" in line:
                    continue
                
                # Regex to extract IP and Hostname
                # Format: Host: 1.1.1.1 (host.name)	Status: Up
                match = re.search(r"Host: ([0-9.]+)\s\((.*?)\)", line)
                if match:
                    ip = match.group(1)
                    hostname = match.group(2) if match.group(2) else "<unknown>"
                    
                    # In GNMAP, "Status: Up" lines are separate or implied
                    # For Grepable format, if the host line exists, it's generally Up
                    host_data.append({
                        "correlation_id": correlation_id,
                        "ip_address": ip,
                        "hostname": hostname,
                        "host_status": "up",
                        "type": "HOST_STATUS"
                    })

        return pd.DataFrame(host_data).drop_duplicates(subset=['ip_address'])

    except Exception as e:
        logging.error(json.dumps({"event": "HOST_STATUS_PARSE_GNMAP_ERROR", "error": str(e)}))
        return pd.DataFrame()

def collect_nmap_ports_gnmap(gnmap_path, config=None):
    """
    Parses Nmap GNMAP to return a DataFrame focusing on port and service status.
    One row per port found on each host.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    port_rows = []

    try:
        with open(gnmap_path, 'r') as f:
            for line in f:
                if "Ports:" not in line:
                    continue

                # Extract IP
                ip_match = re.search(r"Host: ([0-9.]+)", line)
                ip = ip_match.group(1) if ip_match else "<unknown>"

                # Extract everything after Ports:
                ports_part = line.split("Ports: ")[1].strip()
                # Ports are comma separated: 80/open/tcp//http//, 443/open/tcp//https//
                port_entries = ports_part.split(", ")

                for entry in port_entries:
                    parts = entry.split("/")
                    if len(parts) >= 4:
                        port_id = parts[0].strip()
                        port_state = parts[1].strip()
                        protocol = parts[2].strip()
                        service_name = parts[4].strip() if parts[4] else "unknown"
                        product = parts[5].strip() if len(parts) > 5 else ""

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
        logging.error(json.dumps({"event": "PORT_DETAIL_PARSE_GNMAP_ERROR", "error": str(e)}))
        return pd.DataFrame()

def collect_merged_nmap_report_gnmap(gnmap_path, config=None):
    """
    Merges host status and port details from GNMAP into a single flattened DataFrame.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    
    df_hosts = collect_nmap_hosts_gnmap(gnmap_path, config)
    df_ports = collect_nmap_ports_gnmap(gnmap_path, config)

    if df_hosts.empty:
        logging.warning(json.dumps({
            "event": "MERGE_FAILED",
            "correlation_id": correlation_id,
            "message": "No host data found in GNMAP"
        }))
        return pd.DataFrame()

    merged_df = pd.merge(
        df_ports, 
        df_hosts[['ip_address', 'hostname', 'host_status']], 
        on='ip_address', 
        how='left'
    )

    column_order = [
        'correlation_id', 'ip_address', 'hostname', 'host_status', 
        'port', 'protocol', 'port_state', 'service_name', 'version'
    ]
    
    existing_cols = [c for c in column_order if c in merged_df.columns]
    merged_df = merged_df[existing_cols]

    logging.info(json.dumps({
        "event": "NMAP_GNMAP_MERGE_COMPLETE",
        "correlation_id": correlation_id,
        "total_records": len(merged_df),
        "unique_hosts": merged_df['ip_address'].nunique() if not merged_df.empty else 0
    }))

    return merged_df    

def collect_nmap_subnets_gnmap(gnmap_path, subnet_mask='/24', config=None):
    """
    Identifies all unique networks found in the scan results.
    Useful for grouping findings by network segment.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    networks = set()

    try:
        with open(gnmap_path, 'r') as f:
            for line in f:
                match = re.search(r"Host: ([0-9.]+)", line)
                if match:
                    ip_str = match.group(1)
                    # Create a network object based on the IP and desired mask
                    # strict=False allows calculating the network address from a host IP
                    interface = ipaddress.IPv4Interface(f"{ip_str}{subnet_mask}")
                    networks.add(str(interface.network))

        subnet_data = [{
            "correlation_id": correlation_id,
            "subnet": net,
            "type": "SUBNET_IDENTIFIED"
        } for net in networks]

        return pd.DataFrame(subnet_data)

    except Exception as e:
        logging.error(json.dumps({"event": "SUBNET_PARSE_ERROR", "error": str(e)}))
        return pd.DataFrame()

def collect_nmap_subnet_members_gnmap(gnmap_path, subnet_mask='/24', config=None):
    """
    Returns a mapping of Subnets to Hosts.
    One row per Host, including its parent Subnet.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    mapping_rows = []

    try:
        # We reuse the host collector to get validated IP data
        df_hosts = collect_nmap_hosts_gnmap(gnmap_path, config)
        
        if df_hosts.empty:
            return pd.DataFrame()

        for _, row in df_hosts.iterrows():
            ip_str = row['ip_address']
            try:
                # Calculate the network address for the host
                interface = ipaddress.IPv4Interface(f"{ip_str}{subnet_mask}")
                parent_network = str(interface.network)
                
                mapping_rows.append({
                    "correlation_id": correlation_id,
                    "subnet": parent_network,
                    "ip_address": ip_str,
                    "hostname": row['hostname'],
                    "host_status": row['host_status'],
                    "type": "SUBNET_HOST_MAP"
                })
            except ValueError:
                continue # Skip invalid IPs

        return pd.DataFrame(mapping_rows)

    except Exception as e:
        logging.error(json.dumps({"event": "SUBNET_HOST_MAP_ERROR", "error": str(e)}))
        return pd.DataFrame()

def collect_complete_nmap_manifest_gnmap(gnmap_path, subnet_mask='/24', config=None):
    """
    The ultimate merge for GNMAP: Subnet -> Host -> Port.
    Standardizes grepable output into a hierarchical security manifest.
    """
    correlation_id = (config or {}).get('correlation_id', str(uuid.uuid4()))
    config = {"correlation_id": correlation_id}

    # 1. Collect Port/Service data using the GNMAP-specific collector
    df_main = collect_merged_nmap_report_gnmap(gnmap_path, config)
    
    # 2. Collect Subnet Mapping using the GNMAP-specific collector
    df_subnets = collect_nmap_subnet_members_gnmap(gnmap_path, subnet_mask, config)

    if df_main.empty:
        logging.warning(json.dumps({
            "event": "MANIFEST_GEN_EMPTY", 
            "path": gnmap_path, 
            "correlation_id": correlation_id
        }))
        return df_main

    # 3. Final Merge
    # We bring in the 'subnet' column based on ip_address
    manifest_df = pd.merge(
        df_main,
        df_subnets[['ip_address', 'subnet']],
        on='ip_address',
        how='left'
    )

    # 4. Cleanup: Standardize column order for consistency with XML output
    column_order = [
        'correlation_id', 'subnet', 'ip_address', 'hostname', 'host_status', 
        'port', 'protocol', 'port_state', 'service_name', 'version'
    ]
    
    # Ensure all columns exist (important if the GNMAP was partially malformed)
    existing_cols = [c for c in column_order if c in manifest_df.columns]
    manifest_df = manifest_df[existing_cols]

    logging.info(json.dumps({
        "event": "GNMAP_MANIFEST_COMPLETE",
        "correlation_id": correlation_id,
        "rows": len(manifest_df)
    }))

    return manifest_df

def auto_collect(file_path, subnet_mask='/24'):
    if file_path.endswith('.xml'):
        return collect_complete_nmap_manifest_xml(file_path, subnet_mask)
    elif file_path.endswith('.gnmap'):
        return collect_complete_nmap_manifest_gnmap(file_path, subnet_mask)
    else:
        raise ValueError("Unsupported file format")