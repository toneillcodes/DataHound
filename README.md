# DataHound
A versatile data pipeline engine that ingests information from diverse external sources and transforms the extracted node and edge data into the BloodHound OpenGraph format.
## Usage
```
$ python DataHound.py
usage: DataHound.py [-h] [--output OUTPUT] [--base-kind BASE_KIND] [--defs DEFS] [--graphA GRAPHA] [--matchA MATCHA] [--graphB GRAPHB] [--matchB MATCHB] [--edge-kind EDGE_KIND] [--file FILE]
                       [--base-url BASE_URL]
                       {transform,connect}
DataHound.py: error: the following arguments are required: operation
$
```
### Arguments
* 'operation' is a required argument that indicates the task to complete.
  * transform: Parse the transformation definitions file specified by the '--defs' argument, applying the '--base-kind' argument as 'source_kind' and saving the graph to the '--output' file.
  * connect: Correlate the data from two graphs (--graphA and --graphB) and correlate the two sources on the field names from '--matchA' and '--matchB', generate a graph with edge kinds set to '--edge-kind' and output the graph to the '--output' file.
## Examples
- [BloodHound Collector](examples/bloodhound/README.md)
## Todo
* Debug or verbose messages with logging
* Support for encrypted secrets
* Basic authentication web support
* File based input using CSV or JSON formats
* Robust error handling
