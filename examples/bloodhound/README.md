# BloodHound Collector
## Artifacts
- [bloodhound-authority-nodes.json](bloodhound-authority-nodes.json): the 'BHAuthority' nodes that don't have a distinct API source
- [bloodhound-model.json](bloodhound-model.json): the custom icon schema for BloodHound nodes
- [bloodhound-transformation-definitions.json](bloodhound-transformation-definitions.json): transformation definitions for BHE and BHCE
- [sample-bhce-output.json](sample-bhce-output.json): example output  

## APIs Invoked
The following API endpoints are used to collect node and edge data
| API | Endpoint | Source Of |
|---|---|---|
| Users | /api/v2/bloodhound-users | User nodes |
| Users | /api/v2/bloodhound-users | Users -> Roles edges |
| Roles | /api/v2/roles | Role nodes |
| Roles | /api/v2/roles | Role -> Permission edges |
| Permissions | /api/v2/permissions | Permission -> Authority edges |

## Process Overview
1. Upload the custom icon definitions in ```banner-model.json``` to BloodHound using your method of choice

Example using [HoundTrainer](https://github.com/toneillcodes/HoundTrainer)
```
$ python houndtrainer.py upload http://127.0.0.1:8080 -m banner-model.json
Enter JWT: <redacted.redacted.redacted>
[INFO] Uploading model...
[INFO] Model uploaded successfully.
[INFO] Done.
$
```  

2. Upload ```bloodhound-authority-nodes.json``` to  BloodHound using the File Ingest functionality  

4. Update the following properties in ```bloodhound-transformation-definitions.json```  
  a. ```source_url```: update the base URL for the BH installation  
  b. ```source_auth_token```: add a valid JWT  
  
5. Run DataHound to process the transformation definitions and generate an output file
```
$ python DataHound.py --operation collect --source-kind BHCE --config bloodhound-transformations.json --output sample-bhce-output.json
[*] Successfully read config from: bloodhound-transformations.json
[*] Processing Item: Users (Type: node)
[*] Successfully processed 1 nodes.
[*] Processing Item: Roles (Type: node)
[*] Successfully processed 5 nodes.
[*] Processing Item: Permissions (Type: node)
[*] Successfully processed 21 nodes.
[*] Processing Item: User Roles Edges (Type: edge)
[*] Successfully processed 1 edges.
[*] Processing Item: Role Permissions Edges (Type: edge)
[*] Successfully processed 55 edges.
[*] Writing graph to output file: sample-bche-output.json
[>] Wrote graph to sample-bche-output.json
[*] Done.
$
```
5. Upload ```sample-bhce-output.json``` to BloodHound using the File Ingest functionality
