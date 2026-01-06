# DataHound: Nmap Collector

## Overview
The **Nmap Collector** is a high-performance network reconnaissance parser designed to ingest **XML** and **Grepable Nmap (GNmap)** results and transform them into a directed graph. The output is a **BloodHound OpenGraph JSON** file.

By converting flat scan files into an entity-relationship model, security analysts can move beyond text-searching IP addresses and start visualizing the attack surface. This allows for graph-based queries that surface lateral movement vectors and identify high-value service clusters across segmented networks.

<table border="0">
  <tr>
    <td>
      <img src="assets/nmap-example-organic.png" width="100%" />
      <p align="center"><b>Organic Layout</b><br/>Visualizing service distribution</p>
    </td>
    <td>
      <img src="assets/nmap-example-stacked.png" width="100%" />
      <p align="center"><b>Stacked Layout</b><br/>Visualizing subnet membership</p>
    </td>
  </tr>
</table>

## Features
* **Format Agnostic**: Seamlessly handles Nmap XML (`-oX`) and Grepable Nmap (`-oG`) outputs.
* **Network Segmentation**: Automatic identification of subnets based on host density and custom masks.
* **Service Flattening**: Comprehensive breakdown of Ports, Protocols, and Service Versions into discrete nodes.
* **Entity Correlation**: Generates session-specific GUIDs to ensure data integrity when merging multiple scan files.

### Offensive Research (Red Team)
* **Pivoting Analysis**: Visualize "Dual-Homed" hosts or common services across different subnets to find the path of least resistance.
* **Attack Surface Modeling**: Group systems by service version (e.g., all `OpenSSH 7.2`) to quickly identify targets for a specific exploit.
* **Recon Visualization**: Eliminate the manual effort of mapping `.gnmap` files to understand network topology.

### Defensive Research (Blue Team / DFIR)
* **Shadow IT Discovery**: Surface services running on non-standard ports or in unexpected subnets.
* **Vulnerability Triage**: Rapidly map the blast radius of a new vulnerability by querying for the affected service version across the entire graph.
* **Compliance Auditing**: Validate network segmentation by visualizing unauthorized cross-subnet communication paths.

## Core Graph Schema
The collector translates Nmap scan results into the following entity relationship model:

### Nodes
* **NmapSubnet**: The logical network boundary (e.g., `192.168.1.0/24`). Acts as a parent container for hosts.
* **NmapHost**: The individual system identified (identified by IP). Contains hostname and up/down status.
* **NmapPort**: Individual service instances found on a host. Contains port ID, protocol, and state.
* **NmapService**: The identified application (e.g., `http`, `ms-wbt-server`). Contains version and product metadata.

### Edges
* **Subnet** -[:ContainsHost]-> **NmapHost**: Defines physical or logical network membership.
* **NmapHost** -[:HasOpenPort]-> **NmapPort**: Maps the open attack surface of a specific IP.
* **NmapPort** -[:RunsService]-> **NmapService**: Links the open port to the identified application and its version.

## Collection Modules
### 1. Host & Subnet Mapping
Extracts the network architecture from the scan:
* **Network Derivation:** Calculates network addresses from host IPs using a configurable `/24` (default) or custom mask.
* **Status Tracking:** Captures whether hosts were reachable during the scan duration.

---

### 2. Service & Port Analysis
Provides a granular breakdown of every open port:
* **Unique Identification:** Uses a derived GUID (IP:Port) to prevent node collisions while maintaining visual clarity in the graph.
* **Banner Grabbing Support:** Maps product and version strings directly to the port node.

---

### 3. Unified Manifest Generation
The "Ultimate Merge" module that flattens Subnet, Host, and Port data into a single security-focused DataFrame before JSON serialization.

## Collection Methods
| Function | Description |
|----|----|
| collect_nmap_hosts_xml | Parses XML to return a DataFrame of hosts and their up/down status. |
| collect_nmap_hosts_gnmap | Parses GNmap to return a DataFrame of hosts and their up/down status. |
| collect_nmap_ports_xml | Parses XML to extract port and service status. Generates a `port_guid` (IP:Port) to use as the 'id' field. |
| collect_nmap_ports_gnmap | Parses GNmap to extract port and service status. Generates a `port_guid` (IP:Port) to use as the 'id' field. |
| collect_nmap_subnets_xml | Identifies unique networks (e.g., 10.0.0.0/24) found in the XML results. |
| collect_nmap_subnets_gnmap | Identifies unique networks (e.g., 10.0.0.0/24) found in the Gnmap results. |
| collect_nmap_subnet_members_xml | Returns a mapping of Subnets to Hosts, enriching host data with network details. |
| collect_nmap_subnet_members_gnmap | Returns a mapping of Subnets to Hosts, enriching host data with network details. |

## Configuration
The collector uses a JSON configuration to define how specific Nmap data points map to **Graph properties** for both nodes and edges.

**Nmap Host Node Mapping**
```json
{
    "item_type": "node",
    "item_name": "NmapHost",
    "item_description": "Network Host identified by Nmap",
    "source_type": "nmap",
    "id_location": "ip_address",        
    "column_mapping": {  
        "ip_address": "id",
        "hostname": "name"
    },    
    "output_columns": [            
        "id",
        "name",
        "host_status",
        "correlation_id"
    ],  
    "item_kind": "NmapHost"
}
```

## Invocation
1. Upload the custom icon definitions in ```banner-model.json``` to BloodHound using your method of choice  
Example using [HoundTrainer](https://github.com/toneillcodes/HoundTrainer)
```dos
> python houndtrainer.py upload --type node --url https://bhce.example.com --file nmap-model.json
[INFO] Uploading model from file: nmap-model.json...
Enter JWT:
[INFO] Operation 'upload' for type 'node' with file nmap-model.json was successful.
[INFO] Done.
>
> python .\houndtrainer.py list --type node --url https://bhce.example.com
[INFO] Listing all custom types...
Enter JWT:
[INFO] ID: 108, Kind Name: NmapHost
[INFO] ID: 109, Kind Name: NmapPort
[INFO] ID: 110, Kind Name: NmapSubnet
[INFO] ID: 111, Kind Name: NmapService
[INFO] Done.
>
```

2. Run a collect operation on network scan output with the transformation defintions for either XML ```nmap-collection-definitions-xml.json``` or Gnmap ```nmap-collection-definitions-gnmap.json```
``` dos
> python DataHound.py --operation collect --source-kind Nmap --config nmap-collection-definitions-xml.json --output nmap-graph.json
[INFO] Successfully read config from: nmap-collection-definitions-xml.json
[INFO] Successfully processed Nmap Subnets
[INFO] Successfully added 1 items to nodes.
[INFO] Successfully processed Nmap Scan
[INFO] Successfully added 4 items to nodes.
[INFO] Successfully processed Nmap Ports
[INFO] Successfully added 7 items to nodes.
[INFO] Successfully processed Nmap Services
[INFO] Successfully added 7 items to nodes.
[INFO] Successfully processed NmapHost (dynamic) -> NmapPort (dynamic)
[INFO] Successfully added 7 items to edges.
[INFO] Successfully processed NmapPort (dynamic) -> NmapService (dynamic)
[INFO] Successfully added 7 items to edges.
[INFO] Successfully processed Nmap Subnet membership
[INFO] Successfully added 4 items to edges.
[INFO] Writing graph to output file: nmap-graph.json
[INFO] Successfully Wrote graph to nmap-graph.json
>
```

3. Upload the resulting ```nmap-graph.json``` to BloodHound.

## Use Cases for Cypher Queries
Once loaded into BloodHound, you can run queries that simplify analysis by highlighting relationships.

* **Query 1: Find Hosts with RDP and SMB Open**
```cypher
MATCH (h:NmapHost)-[:HasOpenPort]->(p:NmapPort)
WHERE p.name IN ['3389', '445']
RETURN h
```

* **Query 2: Map Vulnerable Service Versions**
```cypher
MATCH (h:NmapHost)-[:HasOpenPort]->(p:NmapPort)-[:RunsService]->(s:NmapService)
WHERE s.version CONTAINS 'OpenSSH 7.2' OR s.product CONTAINS 'OpenSSH 7.2'
RETURN h, p, s
```

* **Query 3: Find Hosts in a Subnet ("Blast Radius")**
```cypher
MATCH (s:NmapSubnet {objectid: '10.10.110.0/24'})-[r]-(hosts) 
RETURN hosts
```