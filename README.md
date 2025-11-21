# DataHound
A data pipeline engine tha collects data from REST APIs and connects graphs.
## Operations
DataHound performs two operations: 
* collect
* connect
### Collect
This mode reads a JSON configuration file, calls the specified data source, extracts data, normalizes the data into a Pandas DataFrame, and transforms it into BloodHound OpenGraph nodes and edges
```
python DataHound.py collect \
  --config /path/to/config.json \
  --source-kind MyCustomSource \
  --output my_transformed_graph.json
```
#### Configuration Properties
| Property | Description | Required? |
|----|----|----|
| item_type | The type that the entry represents, valid values are 'node' and 'edge'| Y |

### Connect
This mode takes two existing BloodHound OpenGraph JSON files and creates new edges between nodes in the first graph (--graphA) and nodes in the second graph (--graphB).  
* Correlation: Performs an outer merge using Pandas DataFrames to match nodes based on a specified property (--matchA and --matchB).  
* Edge Creation: For successful matches, it generates a new edge object with the specified kind (--edge-kind) connecting the matched nodes.  
* Reporting: Outputs the generated edges and a summary report of matched nodes and "orphans" (nodes that did not find a match in the other graph).
```
python DataHound.py connect \
  --graphA sample-app-users.json \
  --matchA uid \
  --graphB other-app-users.json \
  --matchB id \
  --edge-kind MapsTo \
  --output new_connections.json
```
## Usage
Help output.
```
$ python DataHound.py
usage: DataHound.py [-h] --operation {collect,connect} --output OUTPUT [--source-kind SOURCE_KIND] [--config CONFIG] [--graphA GRAPHA] [--matchA MATCHA] [--graphB GRAPHB] [--matchB MATCHB]
                       [--edge-kind EDGE_KIND]
DataHound.py: error: the following arguments are required: --operation, --output
$
```
### Global Arguments
| Parameter | Argument Values | Required? | Description |
|----|----|----|----|
| --operation | collect, connect | Y | The primary function to execute. |
| --output | filename | Y | Output file path for the resulting graph JSON. (Default: output_graph.json) |

### Collect Arguments
| Parameter | Argument Values | Required? | Description |
|----|----|----|----|
| --source-kind | SOURCE_KIND | Y | The source_kind to use in the generated graph. |
| --config | CONFIG | Y | Collection definitions and transformation definitions. |

### Connect Arguments
| Parameter | Argument Values | Required? | Description |
|----|----|----|----|
| --graphA | GRAPHA | Y | File name for Graph A to connect to Graph B. |
| --matchA | MATCHA | Y | The name of the parameter in Graph A to match on |
| --graphB | GRAPHB | Y | File name for Graph A to connect to Graph B. |
| --matchB | MATCHB | Y | The name of the parameter in Graph B to match on |

## Examples
- [BloodHound Collector](examples/bloodhound/README.md)
## Todo
* Debug or verbose messages with logging
* Support for encrypted secrets
* Basic authentication web support
* File based input using CSV or JSON formats
* Robust error handling
