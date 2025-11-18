# DataHound
A versatile data pipeline engine that ingests information from diverse external sources and transforms the extracted node and edge data into the BloodHound OpenGraph format.
## Usage
```
$ python DataHound.py
usage: DataHound.py [-h] base_kind input_file output_file
DataHound.py: error: the following arguments are required: base_kind, input_file, output_file
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
