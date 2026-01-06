<p align="center">
  <img width="530" src="assets/datahound.png"><br/>
  <i>Graph The Planet</i>
</p>

# Overview
A modular data pipeline engine built to extract, normalize, and correlate data into the BloodHound OpenGraph framework.

## Quick Start & Prerequisites
DataHound requires Python 3.x and Pandas.
1. Clone the repository
```
git clone https://github.com/toneillcodes/DataHound.git
cd DataHound
```

2. Install dependencies
```
pip install -r requirements.txt
```

## Usage
```
usage: DataHound.py [-h] --operation {collect,connect} --output OUTPUT [--source-kind SOURCE_KIND] [--config CONFIG] [--graphA GRAPHA] [--rootA ROOTA] [--idA IDA] [--matchA MATCHA] [--graphB GRAPHB] [--rootB ROOTB] [--idB IDB] [--matchB MATCHB] [--edge-kind EDGE_KIND]

A versatile data pipeline engine that ingests information from diverse external sources and transforms the extracted node and edge data into the BloodHound OpenGraph format.

options:
  -h, --help            show this help message and exit

General Options:
  --operation {collect,connect}   Operation to complete.
  --output OUTPUT                 Output file path for graph JSON

Collect Options:
  --source-kind SOURCE_KIND       The 'source_kind' to use for nodes in the graph.
  --config CONFIG                 The path to the collection config file.

Connect Options:
  --graphA GRAPHA         Graph containing Start nodes.
  --rootA ROOTA           Element containing the root of the node data (ex: nodes).
  --idA IDA               Element containing the field to use as the start node ID (ex: id) from Graph A.
  --matchA MATCHA         Element containing the field to match on in Graph A.
  --graphB GRAPHB         Graph containing End nodes.
  --rootB ROOTB           Element containing the field to match on in Graph B.
  --idB IDB               Element containing the field to use as the end node ID (ex: id) from Graph B.
  --matchB MATCHB         Element containing the field to match on in Graph B.
  --edge-kind EDGE_KIND   Kind value to use when generating connection edges (ex: MapsTo).
```

## Core Functionality
DataHound operates in two distinct modes: **collect** and **connect**.

### ```collect```: **Data Extraction and Normalization**
The collect operation extracts raw data from external sources (APIs, databases, files), performs initial transformations (like column renaming and type casting), and produces normalized node and edge data compliant with the BloodHound OpenGraph format.

#### How it Works
1. Reads a JSON configuration file defining the source and transformation rules.
2. Calls the specified data source to collect raw data.
3. Transforms the raw data into a Pandas DataFrame for efficient processing.
4. Creates the final BloodHound OpenGraph nodes and edges by calling transformation methods.

#### Collect Usage
```
python DataHound.py --operation collect \
  --config /path/to/config.json \
  --source-kind MyCustomSource \
  --output my_transformed_graph.json
```
Example output for BHCE collection with the HTTP module.
```
$ python DataHound.py --operation collect --source-kind BHCE --config my-bloodhound-collection-definitions.json --output bhce-collection-exmaple.json
[INFO] Successfully read config from: my-bloodhound-collection-definitions.json
[INFO] Processing Item: Users (Type: node)
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "c8205c99-2ebd-4494-926b-c9e760fc8cd4", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.03598, "content_length": 16699}
[INFO] Successfully processed 5 nodes.
[INFO] Processing Item: Roles (Type: node)
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "79c72ffd-f670-4a72-a69c-7c07ae14181a", "url": "http://127.0.0.1:8080/api/v2/roles", "status_code": 200, "elapsed_seconds": 0.012322, "content_length": 11990}
[INFO] Successfully processed 5 nodes.
[INFO] Processing Item: Permissions (Type: node)
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "ffd005fc-19dc-4568-ba83-a4268aeaa9a9", "url": "http://127.0.0.1:8080/api/v2/permissions", "status_code": 200, "elapsed_seconds": 0.017549, "content_length": 4106}
[INFO] Successfully processed 21 nodes.
[INFO] Processing Item: SSO Providers (Type: node)
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "eccb7a40-5f0d-42c0-b3d1-94c0f82c7c07", "url": "http://127.0.0.1:8080/api/v2/sso-providers", "status_code": 200, "elapsed_seconds": 0.012122, "content_length": 961}
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: User Roles Edges (Type: edge)
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "f7b1a952-e482-4bf2-8caf-6dd1021d13d8", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.01173, "content_length": 16699}
[INFO] Successfully processed 5 edges.
[INFO] Processing Item: Role Permissions Edges (Type: edge)
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "6b6acc5d-f77f-4ab1-bef8-412ca69da669", "url": "http://127.0.0.1:8080/api/v2/roles", "status_code": 200, "elapsed_seconds": 0.015697, "content_length": 11990}
[INFO] Successfully processed 55 edges.
[INFO] Processing Item: User SSO Provider Edges (Type: edge)
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "7c3c9644-22c7-4de2-a501-4a89e92388ae", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.011963, "content_length": 16699}
[INFO] Successfully processed 1 edges.
[INFO] Writing graph to output file: bhce-collection-exmaple.json
[INFO] Successfully Wrote graph to bhce-collection-exmaple.json
[INFO] Done.
$
```

#### Supported Collectors
| Type | Description |
|----|----|
| CSV | Generic file-based CSV collector |
| DPAPI | Windows DPAPI blob and master key collector |
| Host | Generic Host collector for Windows and Linux Computers |
| HTTP | Generic HTTP collector |
| JSON | Generic file-based JSON collector |
| LDAP | Generic LDAP collector |
| Nmap | Nmap XML and Gnmap output collectors |
| PE | Windows Portable Execuable file format collector |
| SMB | Windows Server Message Block (SMB) share collector |
| XML | Generic file-based XML collector |
| YAML | Generic file-based YAML collector |

* Review the [Collector Guide](CollectorGuide.md) for an expanded list of collectors in development, the status and any known limitations or issues.
* Review the [Collector Configuration Guide](CollectorConfigurationGuide.md) for details on the JSON file format and available properties for existing collectors (e.g., ```source_type```, ```column_mapping```).

#### Arguments
| Parameter | Argument Values | Description |
|----|----|----|
| --operation | collect | The primary function to execute. |
| --config | filename | Collection definitions and transformation definitions. |
| --source-kind | source_kind | The source_kind to use in the generated graph. |
| --output | filename | Output file path for the resulting graph JSON. (Default: output_graph.json) |

## Examples
Explore  practical examples to see DataHound collect operations in action.
### Collect Examples
- [BloodHound Collector](examples/collection/bloodhound/README.md)
- [LDAP Collector](examples/collection/ldap/README.md)
- [Nmap Collector](examples/collection/nmap/README.md)

### ```connect```: **Graph Correlation and Linking**
The connect operation takes two JSON files (```--graphA``` and ```--graphB```) and creates new edges between nodes that share a common, correlatable property.

#### How it Works
1. Performs an outer merge using Pandas DataFrames to match nodes based on a specified property (--matchA and --matchB).  
2. For successful matches, it generates a new edge object with the specified kind (--edge-kind) connecting the matched nodes.  
3. Outputs the generated edges in to a new graph file

#### Connect Usage
Example usage connecting a BHCE graph to the Azure sample data set.
```
python DataHound.py --operation connect \
--graphA dev\bhce-collection-20251204.json --rootA nodes --idA id --matchA properties.email \
--graphB entra_sampledata\azurehound_example.json --rootB data --idB data.id --matchB data.userPrincipalName \
--edge-kind MapsTo --output ..\bhce-connected-to-azure.json
```
Example output
```
$ python DataHound.py --operation connect \
--graphA dev\bhce-collection-20251204.json --rootA nodes --idA id --matchA properties.email \
--graphB entra_sampledata\azurehound_example.json --rootB data --idB data.id --matchB data.userPrincipalName \
--edge-kind MapsTo --output ..\bhce-connected-to-azure.json
[INFO] Correlating dev\bhce-collection-20251204.json (root: nodes) and entra_sampledata\azurehound_example.json (root: data) using keys 'properties.email' and 'data.userPrincipalName'.
[INFO] Success! Output written to: ..\bhce-connected-to-azure.json
[INFO] Successfully connected graphs with MapsTo edge kind.
[INFO] Done.
$
```
#### Arguments
| Parameter | Argument Values | Description |
|----|----|----|
| --operation | connect | The primary function to execute. |
| --graphA | filename | File name for Graph A to connect to Graph B. |
| --rootA | NA | The data element that contains the node data to process. |
| --idA | NA | The data element that contains the node ID to use in the edge output. |
| --matchA | NA | The name of the parameter in Graph A to match on. |
| --graphB | filename | File name for Graph A to connect to Graph B. |
| --rootB | NA | The data element that contains the node data to process. |
| --idB | NA | The data element that contains the node ID to use in the edge output. |
| --matchB | NA | The name of the parameter in Graph B to match on. |
| --edge-kind| NA | The edge kind value to use for the generated JSON. |
| --output | filename | Output file path for the resulting graph JSON. (Default: output_graph.json) |

## Examples
Explore  practical examples to see DataHound in action.
### Connect Examples
- Connecting Two Sample OG Graphs with a Static Edge
- Connecting a Sample OG Graphs with the Sample AD Data Set
- Connecting a Sample OG Graphs with the Sample Azure Data Set

## Todo & Future Features
* Debug or verbose messages with logging
* Support for encrypted secrets
* Basic authentication HTTP collector
* ~File based collectors using CSV and JSON formats~
* Robust error handling