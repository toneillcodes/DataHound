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
## Examples
- [BloodHound Collector](examples/bloodhound/README.md)
## Todo
* Debug or verbose messages with logging
* Support for encrypted secrets
* Basic authentication web support
* File based input using CSV or JSON formats
* Robust error handling
