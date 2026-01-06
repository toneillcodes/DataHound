# DataHound: DPAPI Collector

## Overview
The **DPAPI Collector** is a specialized forensic utility designed to locate and parse Windows Data Protection API (DPAPI) blobs and their associated MasterKeys. By reconstructing the relationship between encrypted files, the MasterKeys required to decrypt them, and the User SIDs who own them, this collector generates a **BloodHound OpenGraph JSON** file.

Representing DPAPI structures as a graph allows researchers to bypass the complexity of manual registry and filesystem carving. It enables instant visualization of which user credentials or system secrets are at risk based on the discovery of orphaned or accessible MasterKeys.

> ⚠️ **Warning:** This content is still under development and will change. Some features mentioned are part of near-future development.

<p align="center">
  <img width="600" src="assets/dpapi-blob-to-masterkey-example.png"><br/>
  Mapping encrypted Chrome credentials to their parent DPAPI MasterKey and User SID.
</p>

## Features
* **Blob Discovery**: Automated recursive scanning for the `01000000D08C9DDF...` DPAPI magic header across the filesystem.
* **MasterKey Correlation**: Precise extraction of MasterKey GUIDs from encrypted blobs to identify decryption dependencies.
* **SID Resolution**: Integrated Windows API support to resolve Owner SIDs into human-readable `Domain\Username` formats.
* **Metadata Extraction**: Captures cryptographic parameters including Salt, PBKDF2 iterations, and versioning for both blobs and keys.

### Offensive Research (Red Team)
* **Credential Hunting**: Rapidly identify which MasterKeys need to be targeted (via Mimikatz or DonPPCopy) to unlock high-value blobs like Chrome/Edge passwords or Outlook credentials.
* **Privilege Escalation Paths**: Map relationships between service accounts and system-wide DPAPI MasterKeys located in `C:\Windows\System32\Microsoft\Protect`.
* **Persistence Analysis**: Visualize which secrets are tied to specific users, helping to prioritize which accounts to "stick" to for long-term access.

### Defensive Research (Blue Team / DFIR)
* **Secret Exposure Triage**: Determine the scope of a credential leak by identifying all files encrypted with a compromised MasterKey.
* **Forensic Auditing**: Identify "deleted" or orphaned account activity by flagging SIDs that no longer resolve to active directory objects but still own encrypted data.
* **Host Hardening**: Locate sensitive DPAPI blobs stored in non-standard or insecure directories.

## Core Graph Schema
The collector translates the DPAPI ecosystem into the following entity relationship model:

### Nodes
* **DPAPIBlob**: An encrypted file found on the system. Contains the file path, internal description, and the required MasterKey GUID.
* **DPAPIMasterKey**: The structural key file required for decryption. Contains the version, salt, and PBKDF2 iteration count.
* **UserSID**: The security principal that owns the MasterKey. Enriched with resolved `Domain\Username` data.
* **WindowsHost**: The system where the artifacts were collected (when `collect_computer_info` is enabled).

### Edges
* **DPAPIBlob** -[:RequiresKey]-> **DPAPIMasterKey**: Defines the cryptographic dependency between a blob and its key.
* **UserSID** -[:OwnsKey]-> **DPAPIMasterKey**: Links the MasterKey to the specific user profile it belongs to.
* **WindowsHost** -[:HostContains]-> **DPAPIBlob**: Maps the physical location of the encrypted secret to a host.

## Collection Modules
### 1. Blob Metadata & Magic Parsing
Performs inspection of files to find DPAPI headers:
* **Magic Header Search:** Scans for the 20-byte DPAPI provider signature.
* **Provider GUID Extraction:** Identifies the exact MasterKey GUID needed for the file.
* **UTF-16LE Parsing:** Decodes internal DPAPI descriptions (e.g., "Google Chrome Password").

---

### 2. MasterKey Analysis & SID Resolution
Locates the physical MasterKey files in `APPDATA` or `System32`:
* **SID-to-Name Mapping:** Uses `win32security` to resolve the directory owner's SID to a username.
* **Crypto-Parameter Extraction:** Extracts the 16-byte salt and the iteration count for offline brute-forcing preparation.

## Collection Methods
| Function | Description |
|----|----|
| collect_dpapi_blob_data | Scans directory for blobs, extracts MasterKey GUIDs and UTF-16 descriptions. |
| collect_masterkey_data | Locates physical MasterKey files and parses their headers (Salt, Iterations). |
| resolve_sid | Converts a Windows SID string into a Domain\Username format via Win32 API. |
| collect_windows_host_enumeration | Cross-references DPAPI data with host metadata (Hostname, OS Version). |

## Configuration
The collector uses a JSON configuration to define the scope of the search and metadata enrichment.

**DPAPI Blob Mapping Example**
```json
{
    "item_type": "node",
    "item_name": "DPAPIBlob",
    "source_type": "dpapi",
    "source_path": "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\",
    "collect_computer_info": true,
    "column_mapping": {
        "file_name": "name",
        "master_key_guid": "MK_GUID"
    },
    "item_kind": "DPAPIBlob"
}
```

## Invocation
Running a collect operation to find blobs in a specific user profile:
```dos
> python DataHound.py --operation collect --source-kind DPAPI --config dpapi-transformation-defintions.json --output dpapi-graph.json
[INFO] Scanning C:\Users\Target\AppData for DPAPI Magic...
[INFO] [DPAPI_BLOB_FOUND] file: Login Data, mk_guid: {a1b2c3d4...}
[INFO] [MASTERKEY_FOUND] Owner: DOMAIN\Target, SID: S-1-5-21...
[INFO] Successfully merged host information.
[INFO] Writing graph to output file: dpapi-graph.json
[INFO] Done.
>
```

## Use Cases for Cypher Queries

* **Query 1: Find Chrome/Edge Credential Dependencies** Identify which user accounts own the keys for browser passwords.
```cypher
MATCH (b:DPAPIBlob)-[:RequiresKey]->(k:DPAPIMasterKey)<-[:OwnsKey]-(u:UserSID)
WHERE b.description CONTAINS 'Chrome' OR b.description CONTAINS 'Edge'
RETURN u.name, b.file_path, k.GUID
```

Query 2: Find MasterKeys with Low Iteration Counts Identify potentially weaker keys that are easier to crack offline.
```cypher
MATCH (k:DPAPIMasterKey)
WHERE k.Iterations < 4000
RETURN k.GUID, k.Username, k.Iterations
ORDER BY k.Iterations ASC
```

Query 3: Map System-Owned Secrets Identify blobs that require the SYSTEM MasterKey (found in System32).
```cypher
MATCH (h:WindowsHost)-[:StoredOn]->(b:DPAPIBlob)
WHERE b.file_path CONTAINS 'System32'
RETURN h.name, b.file_path
```