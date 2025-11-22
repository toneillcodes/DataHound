# Collector Configuration Guide
DataHound employs a modular architecture for collectors, ensuring a clean, organized, and highly scalable codebase. This approach encapsulates the logic for each specific data source into independent modules, which delivers two critical benefits: simplified maintenance (allowing changes to one collector without risking others) and maximum reusability (making it easy to adapt or share individual collector components).

The DataHound Collector Configuration file defines the what, where, and how of data extraction and normalization. This file contains an array of definitions, where each object within the array represents a single Collector Module designed to fetch a specific data set.

## Configuration Structure
The file must be a JSON array containing one or more collector definition objects:
```
[
  {
    // Collector Definition 1
    "name": "ActiveDirectoryUsers",
    "source_type": "ldap",
    "source_details": {
      // connection parameters
    },
    "column_mapping": {
      // translation rules
    },
    "output_columns": [
      // final schema definition
    ],
    "id_location": "objectGUID"
  },
  {
    // Collector Definition 2
    // ...
  }
]
```

## Configuration Properties
### Common
| Property | Description | Valid Values | Required? |
|----|----|----|----|
| item_type | The type that the entry represents. | Valid values are 'node' and 'edge'. | Y |
| item_name | An identifier for the collection entry. | NA | Y |
| item_description | A brief description for the collection entry. | NA | Y |
| source_type | Determines which connector is used to collect data. | Valid values are 'http' and 'ldap'. | Y |
| column_mapping | Data transformation definition that translates raw field names to standard names used in the graph output. | NA | N |
| output_columns | Output columns are filtered down to the list defined in this property. | NA | N |
| id_location | The name of the raw data field that contains the 'id' value. | NA | N |
| item_kind | The 'kind' value to use for the item in the graph output. | NA | N |
| source_name | A value or string that identifies the source of the data and gets added to the graph output for information purposes. | NA | N |

### HTTP Source
| Property | Description | Valid Values | Required? |
|----|----|----|----|
| source_url | The URL to call | NA | Y |
| data_root | The root node within the JSON tree that contains the data to process. | NA | Y |
| source_auth_type | Identifies the authentication type for the request. | Valid values are 'bearer-token'. Y |
| source_auth_token | Token for the HTTP request. Required when source_auth_type is 'bearer-token'. | NA | N |
| data_root | The name of the data element that contains the root JSON object to process. | NA | Y |
* Todo: rename these consistently

### LDAP Source
| Property | Description | Valid Values | Required? |
|----|----|----|----|
| ldap_base_dn | The base DN to search from. | NA | Y |
* Todo: rename these consistently