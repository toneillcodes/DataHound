# DataHound
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

## Core Functionality
DataHound operates in two distinct modes: **collect** and **connect**.

### ```collect```: **Data Extraction and Normalization**
The collect operation extracts raw data from external sources (APIs, databases, files), performs initial transformations (like column renaming and type casting), and produces normalized node and edge data compliant with the BloodHound OpenGraph format.

#### How it Works
1. Reads a JSON configuration file defining the source and transformation rules.
2. Calls the specified data source to collect raw data.
3. Transforms the raw data into a Pandas DataFrame for efficient processing.
4. Creates the final BloodHound OpenGraph nodes and edges.

#### Example Usage
```
python DataHound.py --operation collect \
  --config /path/to/config.json \
  --source-kind MyCustomSource \
  --output my_transformed_graph.json
```

#### Collector List
| Type | Description | Status |
|----|----|----|
| HTTP | Generic HTTP collector | Built |
| LDAP | Generic LDAP collector | Built |
| JSON File | Generic file-based JSON collector | Planned |
| CSV File | Generic file-based CSV collector | Planned |

* Review the [Collector Configuration](CollectorConfiguration.md) guide for details on the JSON file format and available properties (e.g., ```source_type```, ```column_mapping```).

#### Arguments
| Parameter | Argument Values | Required? | Description |
|----|----|----|----|
| --operation | {collect,connect} | Y | The primary function to execute. |
| --config | filename | Y | Collection definitions and transformation definitions. |
| --source-kind | source_kind | Y | The source_kind to use in the generated graph. |
| --output | filename | Y | Output file path for the resulting graph JSON. (Default: output_graph.json) |


### ```connect```: **Graph Correlation and Linking**
The connect operation takes two existing BloodHound OpenGraph JSON files (```--graphA``` and ```--graphB```) and creates new edges between nodes that share a common, correlatable property.

#### How it Works
1. Performs an outer merge using Pandas DataFrames to match nodes based on a specified property (--matchA and --matchB).  
2. For successful matches, it generates a new edge object with the specified kind (--edge-kind) connecting the matched nodes.  
3. Outputs the generated edges and a summary report of matched nodes and "orphans" (nodes that did not find a match in the other graph).

#### Example Usage
```
python DataHound.py --operation connect \
  --graphA sample-app.json \
  --matchA uid \
  --graphB other-app.json \
  --matchB username \
  --edge-kind MapsTo \
  --output new_connections.json
```
#### Arguments
| Parameter | Argument Values | Required? | Description |
|----|----|----|----|
| --operation | {collect,connect} | Y | The primary function to execute. |
| --graphA | filename | Y | File name for Graph A to connect to Graph B. |
| --matchA | NA | Y | The name of the parameter in Graph A to match on |
| --graphB | filename | Y | File name for Graph A to connect to Graph B. |
| --matchB | NA | Y | The name of the parameter in Graph B to match on |
| --output | filename | Y | Output file path for the resulting graph JSON. (Default: output_graph.json) |

## Examples
Explore  practical examples to see DataHound in action:
### Collect Exampls
- [BloodHound Collector](examples/collection/bloodhound/README.md)
- [LDAP Collector](examples/collection/ldap/README.md)
### Connect Examples
- Connecting Two Sample OG Graphs with a Static Edge

## Todo & Future Features
* Debug or verbose messages with logging
* Support for encrypted secrets
* Basic authentication HTTP collector
* File based collectors using CSV and JSON formats
* Robust error handling