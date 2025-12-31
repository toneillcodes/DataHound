# Collector Guide
DataHound employs a modular architecture for collectors, ensuring a clean, organized, and highly scalable codebase. This approach encapsulates the logic for each specific data source into independent modules, which delivers two critical benefits: simplified maintenance (allowing changes to one collector without risking others) and maximum reusability (making it easy to adapt or share individual collector components).

## Architectural Overview: The Collection Flow
The DataHound core engine manages scheduling, authentication, and destination handling. The collector's sole responsibility is the Extraction Layer.
When a job executes, the core engine performs the following:
1. Reads the job configuration's source_type.
2. Instantiates the corresponding collector module using the source_processors dict (example):
```
    source_processors = {
        "url": process_http_source,
        "ldap": process_ldap_source,
        "csv": process_csv_source,
        "json": process_json_source,
        "pe": process_pe_source,
        "pe_iat": process_pe_iat_source,
        "pe_iat_entries": process_pe_iat_entries_source,
        "pe_iat_imports": process_pe_dll_imports,
        "pe_eat": process_pe_eat_source,
        "pe_sections": process_pe_sections_source,
        "dpapi_blob": process_dpapi_blob,
        "windows_host": process_windows_host_source
    }
```    
3. Validates the config properties and calls the required extraction function passing the config object.
4. Collector processes the raw data and builds a DataFrame with the required elements.
5. Instantiates the corresponding transformation function using the TRANSFORMERS dict (example):
```
    # dictionary of transform functions
    TRANSFORMERS = {
        'node': transform_node,
        'edge': transform_edge,
        'static_edge': transform_edge,
        'hybrid_edge': transform_edge
    }
```  
6. Append the resulting nodes and edges to the corresponding section of the graph and write the data to the output file.

## Collector Matrix
| Type | source_type ID | Description | Status |
|----|----|----|----|
| CSV File | file_csv | Generic file-based CSV collector | Development |
| DPAPI | dpapi_blob | Windows DPAPI blob and master key collector | Development |
| Host | host_windows | Generic Host collector for Windows and Linux Computers | Development |
| HTTP | url | Generic HTTP collector | Development |
| JSON File | file_json | Generic file-based JSON collector  Development |
| LDAP | ldap | Generic LDAP collector | Development |
| NMap | nmap_xml | NMap XML output collector | Development |
| PE | pe | Windows Portable Execuable file format collector | Development |
| PE | pe_sections | Windows Portable Execuable file format collector | Development |
| PE | pe_iat | Windows Portable Execuable file format collector | Development |
| PE | pe_iat_entries | Windows Portable Execuable file format collector | Development |
| PE | pe_eat | Windows Portable Execuable file format collector | Development |
| SMB | smb | Windows Server Message Block (SMB) share collector | Development |
| XML | file_xml | Generic file-based XML collector | Development |
| YAML | file_yaml | Generic file-based YAML collector | Planned |

## Known Collector Limitations
### HTTP Collector
* Only supports GET requests
* Only supports JSON response data
* No support for pagination, requires multiple defined requests
### HTTP Collector