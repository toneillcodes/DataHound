# Collector Configuration Guide
DataHound employs a modular architecture for collectors, ensuring a clean, organized, and highly scalable codebase. This approach encapsulates the logic for each specific data source into independent modules, which delivers two critical benefits: simplified maintenance (allowing changes to one collector without risking others) and maximum reusability (making it easy to adapt or share individual collector components).

The DataHound Collector Configuration file defines the what, where, and how of data extraction and normalization. This file contains an array of definitions, where each object within the array represents a single Collector Module designed to fetch a specific data set.

## Configuration Structure
The file must be a JSON array containing one or more collector definition objects:
```
[
    // Collector 1: Defines how to collect User data
    {
        "item_type": "node",
        "item_name": "Users",
        "item_description": "Users found in the BloodHound instance",
        "source_type": "url",
        "source_url": "http://127.0.0.1:8080/api/v2/bloodhound-users",
        "source_auth_type": "bearer-token",
        "source_auth_token": "key.key.key",
        "data_root": "users",
        "column_mapping": {
            "id": "id",
            "principal_name": "name",
            "last_login": "last_login"
        },
        "output_columns": [            
            "id",
            "name",
            "last_login"
        ],
        "id_location": "id",        		
        "item_kind": "BHUser",
		    "source_name": "bloodhound-users"
    },
    // Collector 2: Defines how to collect Role data
    {
        "item_type": "node",
        "item_name": "Roles",
        "item_description": "Roles found in the BloodHound instance",
        "source_type": "url",
        "source_url": "http://127.0.0.1:8080/api/v2/roles",
        "source_auth_type": "bearer-token",
        "source_auth_token": "key.key.key",
        "data_root": "roles",  
        "column_mapping": {
            "name": "name",
            "description": "description"
        },
        "output_columns": [
            "name",
            "description"
        ],                            
        "id_location": "name",        		
        "item_kind": "BHRole",
		    "source_name": "roles"
    },
    ...
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