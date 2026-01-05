# DataHound: BloodHound Collector
## Artifacts
- [bloodhound-model.json](bloodhound-model.json): the custom icon schema for BloodHound nodes
- [bloodhound-collection-definitions.json](bloodhound-collection-definitions.json): collection definitions for BHE and BHCE
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
$ python houndtrainer.py upload --type node --url http://127.0.0.1:8080 --file banner-model.json
Enter JWT: <redacted.redacted.redacted>
[INFO] Uploading model...
[INFO] Model uploaded successfully.
[INFO] Done.
$
```  

2. Update the following properties for each item defined in ```bloodhound-transformation-definitions.json```  
  a. ```source_url```: update the base URL for the BH installation  
  b. ```source_auth_token```: add a valid JWT  
  
3. Run DataHound to process the transformation definitions and generate an output file
```
$ python DataHound.py --operation collect --source-kind BHCE --config bloodhound-transformations.json --output sample-bhce-output.json
[INFO] Successfully read config from: bloodhound-transformations.json
[INFO] Processing Item: Tenant (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: Tenant (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: Collection (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: Db (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: App (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: Saved_queries (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: Clients (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: graphdb (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: risks (Type: node)
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: Users (Type: node)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "50066ed3-e7e6-4873-8346-5a7b8b0dc541", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.028607, "content_length": 16699}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "50066ed3-e7e6-4873-8346-5a7b8b0dc541", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.028607, "content_length": 16699}
[INFO] Successfully processed 5 nodes.
[INFO] Processing Item: Roles (Type: node)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "0b2930e3-d182-4a82-a0df-6cab679c57fb", "url": "http://127.0.0.1:8080/api/v2/roles", "status_code": 200, "elapsed_seconds": 0.009714, "content_length": 11990}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "0b2930e3-d182-4a82-a0df-6cab679c57fb", "url": "http://127.0.0.1:8080/api/v2/roles", "status_code": 200, "elapsed_seconds": 0.009714, "content_length": 11990}
[INFO] Successfully processed 5 nodes.
[INFO] Processing Item: Permissions (Type: node)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "563af417-c300-4d7c-bfa3-2a4683377fcd", "url": "http://127.0.0.1:8080/api/v2/permissions", "status_code": 200, "elapsed_seconds": 0.009463, "content_length": 4106}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "563af417-c300-4d7c-bfa3-2a4683377fcd", "url": "http://127.0.0.1:8080/api/v2/permissions", "status_code": 200, "elapsed_seconds": 0.009463, "content_length": 4106}
[INFO] Successfully processed 21 nodes.
[INFO] Processing Item: SSO Providers (Type: node)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "470e7cb0-98c4-411e-86dc-fd76b7ecbc3e", "url": "http://127.0.0.1:8080/api/v2/sso-providers", "status_code": 200, "elapsed_seconds": 0.011221, "content_length": 961}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "470e7cb0-98c4-411e-86dc-fd76b7ecbc3e", "url": "http://127.0.0.1:8080/api/v2/sso-providers", "status_code": 200, "elapsed_seconds": 0.011221, "content_length": 961}
[INFO] Successfully processed 1 nodes.
[INFO] Processing Item: User Roles Edges (Type: edge)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "72d3a96e-64c1-4f2c-8d7d-3db82eccc96d", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.01239, "content_length": 16699}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "72d3a96e-64c1-4f2c-8d7d-3db82eccc96d", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.01239, "content_length": 16699}
[INFO] Successfully processed 5 edges.
[INFO] Processing Item: Role Permissions Edges (Type: edge)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "00324607-a1df-474c-a966-08bf5e59484f", "url": "http://127.0.0.1:8080/api/v2/roles", "status_code": 200, "elapsed_seconds": 0.010156, "content_length": 11990}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "00324607-a1df-474c-a966-08bf5e59484f", "url": "http://127.0.0.1:8080/api/v2/roles", "status_code": 200, "elapsed_seconds": 0.010156, "content_length": 11990}
[INFO] Successfully processed 55 edges.
[INFO] Processing Item: User SSO Provider Edges (Type: edge)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "0dab86c5-b47e-4bbd-8296-079c68a250cc", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.011976, "content_length": 16699}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "0dab86c5-b47e-4bbd-8296-079c68a250cc", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.011976, "content_length": 16699}
[INFO] Successfully processed 1 edges.
[INFO] Processing Item: BHUser (dynamic) -> BHTenant (static) edge (Type: hybrid_edge)
[INFO] {"event": "HTTP_REQUEST_SENT", "correlation_id": "7a9aac3a-1a38-42ae-8936-0f5fa659401e", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.010765, "content_length": 16699}
[INFO] {"event": "HTTP_REQUEST_SUCCESS", "correlation_id": "7a9aac3a-1a38-42ae-8936-0f5fa659401e", "url": "http://127.0.0.1:8080/api/v2/bloodhound-users", "status_code": 200, "elapsed_seconds": 0.010765, "content_length": 16699}
[INFO] Successfully processed 5 hybrid_edges.
[INFO] Writing graph to output file: sample-bhce-output.json
[INFO] Successfully Wrote graph to sample-bhce-output.json
[INFO] Done.
$
```

4. Upload ```sample-bhce-output.json``` to BloodHound using the File Ingest functionality
