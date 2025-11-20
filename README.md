# DataHound
A versatile data pipeline engine that ingests information from diverse external sources and transforms the extracted node and edge data into the BloodHound OpenGraph format.
## Functionality
The 'operation' arugment is required and indicates the task to complete.  
There are currently two valid values: 'transform' and 'connect'.
### Transform Operation
This mode reads a JSON configuration file (--defs), calls the specified data source, extracts data, normalizes the data into a Pandas DataFrame, and transforms it into BloodHound OpenGraph nodes and edges
```
python DataHound.py transform \
  --defs /path/to/config.json \
  --base-kind MyCustomSource \
  --output my_transformed_graph.json
```
### Connect Operation
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
usage: DataHound.py [-h] [--output OUTPUT] [--base-kind BASE_KIND] [--defs DEFS] [--graphA GRAPHA] [--matchA MATCHA] [--graphB GRAPHB] [--matchB MATCHB] [--edge-kind EDGE_KIND] [--file FILE]
                       [--base-url BASE_URL]
                       {transform,connect}
DataHound.py: error: the following arguments are required: operation
$
```
### Global Arguments
| Argument | Valid Values | Required? | Description |
|----|----|----|----|
| operation | transform, connect | Y | The primary function to execute. |
| --output | (str) | Y | Output file path for the resulting graph JSON. (Default: output_graph.json) |

## Examples
- [BloodHound Collector](examples/bloodhound/README.md)
## Todo
* Debug or verbose messages with logging
* Support for encrypted secrets
* Basic authentication web support
* File based input using CSV or JSON formats
* Robust error handling
