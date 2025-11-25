# Collector Guide
DataHound employs a modular architecture for collectors, ensuring a clean, organized, and highly scalable codebase. This approach encapsulates the logic for each specific data source into independent modules, which delivers two critical benefits: simplified maintenance (allowing changes to one collector without risking others) and maximum reusability (making it easy to adapt or share individual collector components).

## Architectural Overview: The Collection Flow
The DataHound core engine manages scheduling, authentication, and destination handling. The collector's sole responsibility is the Extraction Layer.
When a job executes, the core engine performs the following:
1. Reads the job configuration's source_type.
2. Instantiates the corresponding collector module.
3. Calls the required extraction function, providing configuration and credentials.
4. Receives the raw data as a standardized JSON structure.
5. Passes the data to the transformation and loading layers.

## Collector Matrix
| Type | source_type ID | Description | Status |
|----|----|----|----|
| HTTP | url | Generic HTTP collector | Development |
| LDAP | ldap | Generic LDAP collector | Development |
| JSON File | file_json | Generic file-based JSON collector | Planned |
| CSV File | file_csv | Generic file-based CSV collector | Planned |

## Known Collector Limitations
### HTTP Collector
* Only supports GET requests
* Only supports JSON response data
* No support for pagination, requires multiple defined requests