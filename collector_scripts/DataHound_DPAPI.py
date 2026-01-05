import json
import logging
from collector_modules.dpapi_collector import collect_dpapi_blob_data, collect_masterkey_data

# Configure logging to see the events in the console
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def run_collection():
    # 1. Define the search configuration
    config = {
        "source_path": "C:\\Users\\Admin\\AppData", # Path to scan for blobs
        "collect_computer_info": False,             # Toggle host enumeration
        "bytes_to_read": 2048,                      # How deep to look for magic bytes
        "correlation_id": "DH-999-BETA"
    }

    print(f"[*] Starting DPAPI Blob Collection on: {config['source_path']}")
    
    # 2. Run the Blob Collector
    df_blobs = collect_dpapi_blob_data(config)

    if df_blobs is not None and not df_blobs.empty:
        # Export Blobs to JSON
        blob_output = "dpapi_blobs_results.json"
        df_blobs.to_json(blob_output, orient="records", indent=4)
        print(f"[+] Found {len(df_blobs)} blobs. Results saved to {blob_output}")

        # 3. Optional: Automatically pivot to find MasterKeys for discovered GUIDs
        unique_guids = df_blobs['master_key_guid'].unique()
        all_masterkeys = []

        print(f"[*] Attempting to locate {len(unique_guids)} MasterKey files on system...")
        for guid in unique_guids:
            mk_results = collect_masterkey_data(guid)
            all_masterkeys.extend(mk_results)

        if all_masterkeys:
            mk_output = "dpapi_masterkeys_results.json"
            with open(mk_output, 'w') as f:
                # Use default=str to handle datetime objects in the results
                json.dump(all_masterkeys, f, indent=4, default=str)
            print(f"[+] Found {len(all_masterkeys)} MasterKey files. Results saved to {mk_output}")
    else:
        print("[-] No DPAPI blobs were found in the specified path.")

if __name__ == "__main__":
    run_collection()