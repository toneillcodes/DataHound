from jsonpath_ng import parse as jsonpath_parse
from typing import Any, Dict, List, Optional
from requests.adapters import HTTPAdapter
from json.decoder import JSONDecodeError
from urllib3.util.retry import Retry
import pandas as pd
import requests
import getpass
import logging
import uuid

from . import core

# ldap collector methods
from collector_modules.ldap_collector import collect_ldap_data
# http collector methods
from collector_modules.http_collector import collect_http_data
# csv collector methods
from collector_modules.csv_collector import collect_csv_data
# json collector methods
from collector_modules.json_collector import collect_json_data
# pe collector methods
from collector_modules.pe_collector import get_pe_metadata                      # general PE metadata filename, hashes, size, etc.
from collector_modules.pe_collector import get_sections_dataframe               # Sections dataframe
from collector_modules.pe_collector import get_iat_dataframe                    # IAT dataframe without malapi enrichment
from collector_modules.pe_collector import get_iat_with_malapi_dataframe        # IAT dataframe with malapi enrichment
from collector_modules.pe_collector import get_exports_dataframe                # EAT dataframe
from collector_modules.pe_collector import find_iat_section                     # this method is deprecated (locate IAT VA and section)
from collector_modules.pe_collector import find_eat_section                     # this method is deprecated (locate EAT VA and section)
from collector_modules.pe_collector import get_directory_section_info           # retrieve the VA and corresponding section for a header directory element
from collector_modules.pe_collector import calculate_pe_risk_score              # currently unused
# dpapi collector methods
from collector_modules.dpapi_collector import collect_dpapi_blob_data           # tested
from collector_modules.dpapi_collector import collect_masterkey_data
# host collector methods
from collector_modules.host_collector import collect_windows_host_enumeration   # development
from collector_modules.host_collector import collect_linux_host_enumeration     # untested
# nmap collector methods
# xml nmap output
from collector_modules.nmap_collector import collect_nmap_hosts_xml
from collector_modules.nmap_collector import collect_nmap_ports_xml
from collector_modules.nmap_collector import collect_nmap_subnets_xml
from collector_modules.nmap_collector import collect_nmap_subnet_members_xml
# gnmap nmap output
from collector_modules.nmap_collector import collect_nmap_hosts_gnmap
from collector_modules.nmap_collector import collect_nmap_ports_gnmap
from collector_modules.nmap_collector import collect_nmap_subnets_gnmap
from collector_modules.nmap_collector import collect_nmap_subnet_members_gnmap
# arrows json
from collector_modules.arrows_collector import collect_arrows_node_data
from collector_modules.arrows_collector import collect_arrows_edge_data

# configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# HTTP collector configuration start
# configure global session with retries
API_SESSION = requests.Session()
retry_strategy = Retry(
    total=3,                # Retry up to 3 times
    backoff_factor=1,       # Wait 1s, then 2s, then 4s between retries
    status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP codes
)
API_SESSION.mount("https://", HTTPAdapter(max_retries=retry_strategy))
API_SESSION.mount("http://", HTTPAdapter(max_retries=retry_strategy))
# HTTP collector configuration end

def replace_none_with_string_null(obj):
    """
    Recursively replaces Python None values with the string "null" within
    a dictionary or list.
    """
    if isinstance(obj, dict):
        return {k: replace_none_with_string_null(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_none_with_string_null(elem) for elem in obj]
    elif obj is None:
        return "null"  # Replace None with the string "null"
    else:
        return obj

def get_data_from_source(config, source_type_override=None):
    """
    Centralized dispatcher to fetch a DataFrame from any supported source.
    """
    source_type = source_type_override or config.get('source_type')
    
    # todo: consider renaming these now that the list has grown. 'source' is a bit redundant
    source_processors = {
        "url": process_http_source,
        "ldap": process_ldap_source,
        "csv": process_csv_source,
        "json": process_json_source,
        "pe": process_pe_source,
        "pe_sections": process_pe_sections_source,
        "pe_eat": process_pe_eat_source,
        "pe_eat_entries": process_pe_eat_entries_source,
        "pe_eat_exports": process_pe_dll_exports,
        "pe_iat": process_pe_iat_source,
        "pe_iat_entries": process_pe_iat_entries_source,
        "pe_iat_imports": process_pe_dll_imports,                           
        "dpapi_blob": process_dpapi_blob,                   
        "dpapi_masterkey": process_dpapi_masterkey,         # does this make sense?
        "dpapi_masterkey_sids": process_dpapi_masterkey_sids,         # does this make sense?
        "windows_host": process_windows_host_source,        # todo: add linux host enumeration     
        "nmap_hosts_xml": process_nmap_hosts_xml_source,
        "nmap_ports_xml": process_nmap_ports_xml_source,
        "nmap_subnets_xml": process_nmap_subnets_xml,
        "nmap_subnet_members_xml": process_nmap_subnet_members_xml,
        "nmap_hosts_gnmap": process_nmap_hosts_gnmap,
        "nmap_ports_gnmap": process_nmap_ports_gnmap,
        "nmap_subnets_gnmap": process_nmap_subnets_gnmap,
        "nmap_subnet_members_gnmap": process_nmap_subnet_members_gnmap,    
        "arrows_nodes": process_arrows_nodes_json,    
        "arrows_edges": process_arrows_edges_json,    
        "static": core.generate_static_node # todo: does this naming make sense anymore?
    }

    processor = source_processors.get(source_type)
    if not processor:
        logging.error(f"Unsupported source_type: {source_type}")
        return None
        
    return processor(config)

def process_http_source(config):
    """
    Docstring for process_http_source
    
    :param config: data collection and transformation definition in JSON format
    """
    item_name = config.get('item_name', 'NA')
    
    # validation
    if not config.get('source_url'):
        logging.error(f"'source_url' is required for source_type='url' (Ref: {item_name}). Skipping.")
        return False

    if config.get('source_auth_type') == "bearer-token" and not config.get('source_auth_token'):
        logging.error(f"'source_auth_token' is required for bearer-token auth (Ref: {item_name}). Skipping.")
        return False

    # retrieve data from API endpoint defined in tranformation (config)
    api_response = collect_http_data(config, API_SESSION)

    # todo: add debug output control with additional debug statements
    #logging.debug(f"api_response: {api_response}") 
    
    if api_response is None:
        logging.warning(f"Skipping item {item_name} due to failed API response.")
        return False

    # retrieve the root data element
    data_root_element = config.get('data_root')
    if data_root_element:
        # create a jsonpath expression to find all matches for the data root element recursively             
        jsonpath_expression = jsonpath_parse(f'$..{data_root_element}')
        # check the API response for jsonpath_expression
        path_matches = jsonpath_expression.find(api_response)
        
        # no matches
        if not path_matches:
            logging.error(f"Could not find data root element: {data_root_element} for item {item_name}. Skipping.")
            return False

        first_match = path_matches[0]
        data_object = first_match.value
    else:
        data_object = api_response

    ## todo: add check to validate data_object
    try:
        # sanitize the data to prevent unintended data conversions during the pd.json_normalize operation
        # without this, integer values can be converted into floats
        clean_data_object = replace_none_with_string_null(data_object)
        # flatten JSON
        df = pd.json_normalize(clean_data_object)
        #df = pd.json_normalize(data_object)
        #print(f"df: {df}")
        return df
    except Exception as e:
        logging.error(f"Failed to normalize data for item {item_name}: {e}. Skipping.")
        return False

def process_ldap_source(config):
    """
    Docstring for process_ldap_source
    
    :param config: data collection and transformation definition in JSON format
    """
    item_name = config.get('item_name', 'NA')
    if not config.get('server'):
        logging.error(f"'server' is required. Skipping item: {item_name}.")
        return False
    if not config.get('port'):
        logging.error(f"'port' is required. Skipping item: {item_name}.")
        return False
    if not config.get('bind_dn'):
        logging.error(f"'bind_dn' is required. Skipping item: {item_name}.")
        return False
    if not config.get('ldap_base_dn'):
        logging.error(f"'ldap_base_dn' is required. Skipping item: {item_name}.")
        return False
    # todo: is search_filter required?
    if not config.get('ldap_search_filter'):
        logging.error(f"'ldap_search_filter' is required. Skipping item: {item_name}.")
        return False
    # todo: is ldap_attributes required?
    if not config.get('ldap_attributes'):
        logging.error(f"'ldap_attributes' is required. Skipping item: {item_name}.")
        return False

    # config contains all the required properties, prompt for password
    ldap_password = getpass.getpass("LDAP Bind Password: ")

    # retrieve data from ldap
    ldap_data = collect_ldap_data(config, ldap_password)
    if ldap_data is None:
        logging.warning(f"Skipping item {item_name} due to failed LDAP connection/search.")
        return False
    
    # something was returned, point data_object to it for processing
    # todo: add check to validate data_object
    data_object = ldap_data
    try:
        # sanitize the data to prevent unintended data conversions during the pd.json_normalize operation
        # without this, integer values can be converted into floats
        clean_data_object = replace_none_with_string_null(data_object)
        # flatten JSON
        #df = pd.json_normalize(data_object)
        df = pd.json_normalize(clean_data_object)
        if df:
            logging.info(f"Successfully processed {item_name}")
            return df
        else:
            return False
    except Exception as e:
        logging.error(f"Failed to normalize data for item {item_name}: {e}. Skipping.")
        return False

def process_csv_source(config):
    """
    Docstring for process_csv_source
    
    :param config: data collection and transformation definition in JSON format
    """
    item_name = config.get('item_name', 'NA')
    # validation
    source_path = config.get('input_file')
    if not source_path:
        logging.error(f"'input_file' is required. Skipping item: {item_name}.")
        return False

    # invoke collector
    csv_data = collect_csv_data(config)
    if csv_data is None:
        logging.warning(f"Skipping item {item_name} due to failed parsing of input file.")
        return False
    
    # something was returned, point data_object to it for processing
    #print(f"csv_data: {csv_data}")
    logging.info(f"Successfully processed {item_name}")
    return csv_data

def process_json_source(config):
    """
    Docstring for process_json_source
    
    :param config: data collection and transformation definition in JSON format
    """
    item_name = config.get('item_name', 'NA')
    source_path = config.get('source_path')
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    json_data = collect_json_data(config)
    if json_data is None:
        logging.warning(f"Skipping item {item_name} due to failed parsing of input file.")
        return False
    
    # something was returned, point data_object to it for processing
    #print(f"json_data: {json_data}")
    logging.info(f"Successfully processed {item_name}")
    df = json_data       
    return df

def process_pe_source(config):
    """
    Docstring for process_pe_source
    
    :param config: data collection and transformation definition in JSON format
    """
    item_name = config.get('item_name', 'NA')
    # validation
    if not config.get('source_path'):
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False

    # collect PE metadata
    df_meta = get_pe_metadata(config) 
    if df_meta is None:
        logging.warning(f"Skipping {item_name}: Metadata collection failed.")
        return False
    
    return df_meta

def process_pe_iat_source(config):
    """
    Retrieves EAT information from a Windows PE file and generates a GUID to use in OG
    
    :param config: data collection and transformation definition in JSON format
    """
    item_name = config.get('item_name', 'NA')
    # validation
    source_path = config.get('source_path')
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False

    df_iat = None
    rows = []

    df_meta = get_pe_metadata(config)
    filehash = df_meta['sha256'].iloc[0]

    iat_info = find_iat_section(source_path)    # returns False, iat_va if the data falls outside of a mapped section
    #iat_info = get_directory_section_info(source_path, 'IMAGE_DIRECTORY_ENTRY_IAT')

    #print(f"iat_info: {iat_info}")

    # initialize a value and then determine if it should be a section GUID or the PE GUID
    iat_location_value = None
    if iat_info is None:
        logging.error("Could not find IAT.")
        return None
    elif iat_info:
        iat_location, iat_va = iat_info
        if iat_location is False:
            iat_location_value = f"{filehash}"
        else:
            iat_location_value = iat_location

    # build a dataframe with the information that we need, creating a somewhat static node setting a id and name
    # todo: this needs to be updated to use a GUID for the 'id' field - maybe by appending the PE ID (sha256 hash or another hash?) 
    #       using just filename could lead to collisons
    rows.append({
        "id": f"IAT-{filehash}",
        "name": "IAT",
        "location": f"{iat_location_value}-{filehash}",
        "location_va": hex(iat_va)
    })

    if rows:
        logging.info(f"Successfully processed {item_name}")
        df_iat = pd.DataFrame(rows)

    return df_iat

# todo: consider consolidating IAT and EAT methods
def process_pe_iat_entries_source(config):
    """
    Retrieves IAT entriesfrom a Windows PE file
    
    :param config: data collection and transformation definition in JSON format
    """
    item_name = config.get('item_name', 'NA')
    # validation
    source_path = config.get('source_path')
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False

    # collect encirched IAT data
    #df_iat = get_iat_dataframe(config)
    # todo: consider changing this to use flare-capa
    df_iat = get_iat_with_malapi_dataframe(config)
    if df_iat is None:
        logging.warning(f"Skipping {item_name}: IAT collection failed.")
        return False

    iat_info = find_iat_section(source_path)
    #iat_info = get_directory_section_info(source_path, 'IMAGE_DIRECTORY_ENTRY_IAT')
    if iat_info:
        iat_location, iat_va = iat_info
        df_iat['iat_location'] = iat_location
        df_iat['iat_va'] = hex(iat_va)
    else:
        # Handle the error gracefully
        logging.error("Could not find IAT section.")
        iat_location, iat_va = "Unknown", 0
        
    logging.info(f"Successfully processed {item_name}")
    return df_iat

def process_pe_dll_imports(config):
    """
    Retrieves distinct DLL import references from a Windows PE file
    
    :param config: data collection and transformation definition in JSON format
    """
    df_enriched = None
    # call enriched IAT function
    df_enriched = get_iat_with_malapi_dataframe(config)
    if df_enriched is None or df_enriched.empty:
        # IAT retrieval failed
        return None

    distinct_dll_nodes = None
    # copy only DLL column and filter only distinct entries
    dll_nodes = df_enriched[['DLL']].copy()
    distinct_dll_nodes = dll_nodes.drop_duplicates(subset=['DLL'])
    if distinct_dll_nodes is not None:
        return distinct_dll_nodes
    else:
        return None

def process_pe_dll_exports(config):
    """
    Retrieves distinct DLL export references from a Windows PE file
    
    :param config: data collection and transformation definition in JSON format
    """
    df_export_dlls = None
    # call EAT function
    df_export_dlls = get_exports_dataframe(config)
    if df_export_dlls is None or df_export_dlls.empty:
        # IAT retrieval failed
        return None

    #print(f"df_export_dlls: {df_export_dlls}")
    #print(f"address: {df_export_dlls['Address'].iloc[0]}")

    distinct_dll_nodes = None
    # copy only DLL column and filter only distinct entries
    dll_nodes = df_export_dlls[['DLL']].copy()
    distinct_dll_nodes = dll_nodes.drop_duplicates(subset=['DLL'])
    if distinct_dll_nodes is not None:
        return distinct_dll_nodes
    else:
        return None    
    
# todo: consider consolidating IAT and EAT methods
def process_pe_eat_source(config):
    item_name = config.get('item_name', 'NA')
    # validation
    source_path = config.get('source_path')
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False

    eat_info = find_eat_section(source_path)
    #eat_info = get_directory_section_info(source_path, 'IMAGE_DIRECTORY_ENTRY_EXPORT')
    if eat_info:
        eat_location, eat_va = eat_info
    else:
        logging.error("Could not find EAT section.")
        return False

    df_eat = None
    rows = []

    df_meta = get_pe_metadata(config)
    #print(f"df_meta: {df_meta}")
    filehash = df_meta['sha256'].iloc[0]

    # build an array with the information that we need, creating a somewhat static node setting a id and name
    # todo: this needs to be updated to use a GUID for the 'id' field - maybe by appending the PE ID (sha256 hash or another hash?) 
    #       using just filename could lead to collisons
    rows.append({
        "id": f"EAT-{filehash}",
        "name": "EAT",
        "location": eat_location,
        "location_va": hex(eat_va)
    })
    # convert to dataframe
    df_eat = pd.DataFrame(rows)

    logging.info(f"Successfully processed {item_name}")
    return df_eat

# todo: consider consolidating IAT and EAT methods
def process_pe_eat_entries_source(config):
    item_name = config.get('item_name', 'NA')
    # validation
    source_path = config.get('source_path')
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False

    # collect EAT data
    df_eat = get_exports_dataframe(config)
    if df_eat is None:
        logging.warning(f"Skipping {item_name}: EAT collection failed.")
        return False
        
    # locate EAT to enrich the dataframe
    #eat_info = find_eat_section(source_path) # this method is deprecated
    eat_info = get_directory_section_info(source_path, 'IMAGE_DIRECTORY_ENTRY_EXPORT')
    if eat_info:
        eat_location, eat_va = eat_info
        df_eat['eat_location'] = eat_location
        df_eat['eat_va'] = hex(eat_va)
    else:
        # Handle the error gracefully - this data is not equired so we will attempt to continue
        logging.error("Could not find EAT section.")
        eat_location, eat_va = "Unknown", 0

    # retrieve metadata which contains the file's unique sha256 hash
    df_meta = get_pe_metadata(config)
    #print(f"df_meta: {df_meta}")
    filehash = df_meta['sha256'].iloc[0]
    # use the hash to make a fake GUID to help avoid collisions
    df_eat['eat-guid'] = df_eat.apply(
        lambda row: f"EAT-{filehash}", 
        axis=1
    )

    logging.info(f"Successfully processed {item_name}")
    return df_eat

def process_pe_sections_source(config):
    item_name = config.get('item_name', 'NA')
    # validation
    source_path = config.get('source_path')
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
            
    # collect section data
    df_sections = get_sections_dataframe(config)
    if df_sections is None:
        logging.warning(f"Skipping {item_name}: Section collection failed.")
        return False

    df_meta = get_pe_metadata(config)
    #print(f"df_meta: {df_meta}")
    filehash = df_meta['sha256'].iloc[0]

    # build a dataframe with the information that we need, creating a somewhat static node setting a id and name
    # todo: this needs to be updated to use a GUID for the 'id' field - maybe by appending the PE ID (sha256 hash or another hash?) 
    #       using just filename could lead to collisons
    df_sections['section-guid'] = df_sections.apply(
        lambda row: f"{row['Section_Name']}-{filehash}", 
        axis=1
    )

    # This ignores all column values and just joins everything to everything
    #merged_df = pd.merge(df_sections, df_enriched_id, how="cross")
    #print(f"merged_df: {merged_df}")

    logging.info(f"Successfully processed {item_name}")
    return df_sections

def process_dpapi_blob(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False

    df_dpapi = None
    df_dpapi = collect_dpapi_blob_data(config)
    if df_dpapi is not None:
        logging.info(f"Successfully processed {item_name}")
        return df_dpapi
    else:
        return False

def process_dpapi_masterkey(config):
    df_blobs = collect_dpapi_blob_data(config)
    if df_blobs is None:
        logging.error("Unable to locate DPAPI blobs. Cannot run masterkey collection.")
        return False

    unique_guids = df_blobs['master_key_guid'].dropna().unique()
    all_results = []

    for mk_guid in unique_guids:
        if not mk_guid:
            continue

        # Attempt to enrich via filesystem
        mk_data = collect_masterkey_data(mk_guid) 
        
        if mk_data:
            # mk_data is a list of dictionaries; add them all
            all_results.extend(mk_data)         
        else:
            # FALLBACK: Create a skeleton record so the GUID is preserved
            logging.warning(f"No MasterKey file found for GUID: {mk_guid}. Creating placeholder.")
            all_results.append({
                "GUID": mk_guid,
                "Username": "Unknown (File Missing)",
                "Iterations": "N/A",
                "Created_At": "N/A",
                "Owner_SID": "N/A",
                "Full_Path": "NOT_FOUND_ON_DISK"
            })

    # convert to dataframe
    if all_results:
        df_final = pd.DataFrame(all_results)  
        #cols = ["Username", "GUID", "Iterations", "Created_At", "Owner_SID", "Full_Path"]
        #available_cols = [c for c in cols if c in df_final.columns]
        #return df_final[available_cols]
        return df_final
    
    return pd.DataFrame()

def process_dpapi_masterkey_sids(config):
    """
    Pivots from discovered DPAPI blobs to MasterKey files on disk.
    Returns a DataFrame of unique Owner SIDs and their resolved usernames.
    """
    correlation_id = config.get('correlation_id', str(uuid.uuid4()))
    
    # 1. Get the blobs to find which MasterKey GUIDs we care about
    df_blobs = collect_dpapi_blob_data(config)
    if df_blobs is None or df_blobs.empty:
        logging.error("Unable to locate DPAPI blobs. Cannot run masterkey collection.")
        return pd.DataFrame()

    unique_guids = df_blobs['master_key_guid'].dropna().unique()
    all_masterkeys = []

    # 2. Search for the MasterKey files on the filesystem
    for mk_guid in unique_guids:
        mk_data = collect_masterkey_data(mk_guid) 
        if mk_data:
            all_masterkeys.extend(mk_data)
        else:
            logging.warning(f"MasterKey file not found on disk for GUID: {mk_guid}")

    if not all_masterkeys:
        return pd.DataFrame()

    # 3. Process the MasterKey list into Unique SIDs
    df_mk = pd.DataFrame(all_masterkeys)
    
    # Filter for unique Owner_SID values only
    # We want to know who owns the keys, not necessarily every individual key file
    unique_sids = df_mk[['Owner_SID', 'Username']].drop_duplicates(subset=['Owner_SID'])

    # 4. Format for DataHound processing
    sid_results = []
    for _, row in unique_sids.iterrows():
        sid_results.append({
            "correlation_id": correlation_id,
            "sid": row['Owner_SID'],
            "resolved_name": row['Username'],
            "type": "USER_SID_IDENTIFIED"
        })

    return pd.DataFrame(sid_results)

def process_windows_host_source(config):
    item_name = config.get('item_name', 'NA')
    df_host = None
    df_host = collect_windows_host_enumeration(config)
    if df_host is not None:
        logging.info(f"Successfully processed {item_name}")
        return df_host
    else:
        return False

def process_nmap_hosts_xml_source(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
    
    df_nmap = None
    df_nmap = collect_nmap_hosts_xml(source_path)
    if df_nmap is not None:
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False
    
def process_nmap_ports_xml_source(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    df_nmap = None
    df_nmap = collect_nmap_ports_xml(source_path)
    if df_nmap is not None:
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False

def process_nmap_subnets_xml(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    df_nmap = None
    df_nmap = collect_nmap_subnets_xml(source_path)
    if df_nmap is not None:
        #print(f"df_nmap: {df_nmap}")
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False
    
def process_nmap_subnet_members_xml(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    df_nmap = None
    df_nmap = collect_nmap_subnet_members_xml(source_path)
    if df_nmap is not None:
        #print(f"df_nmap: {df_nmap}")
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False

def process_nmap_hosts_gnmap(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    df_nmap = None
    df_nmap = collect_nmap_hosts_gnmap(source_path)
    if df_nmap is not None:
        #print(f"df_nmap: {df_nmap}")
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False
        
def process_nmap_ports_gnmap(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    df_nmap = None
    df_nmap = collect_nmap_ports_gnmap(source_path)
    if df_nmap is not None:
        #print(f"df_ports_nmap: {df_nmap}")
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False
    
def process_nmap_subnets_gnmap(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    df_nmap = None
    df_nmap = collect_nmap_subnets_gnmap(source_path)
    if df_nmap is not None:
        # a 1:1 relationship between the scan and the graph node.
        df_nmap = df_nmap.drop_duplicates(subset=['subnet'])
        #print(f"df_nmap: {df_nmap}")
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False
    
def process_nmap_subnet_members_gnmap(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
        
    df_nmap = None
    df_nmap = collect_nmap_subnet_members_gnmap(source_path)
    if df_nmap is not None:
        #print(f"df_nmap: {df_nmap}")
        logging.info(f"Successfully processed {item_name}")
        return df_nmap
    else:
        return False
    
def process_arrows_nodes_json(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
    df_arrows_nodes = collect_arrows_node_data(config)
    if df_arrows_nodes  is not None:
        #print(f"df_arrows_nodes: {df_arrows_nodes}")
        logging.info(f"Successfully processed {item_name}")
        return df_arrows_nodes
    else:
        return False        
    
def process_arrows_edges_json(config):
    item_name = config.get('item_name', 'NA')
    source_path  = config.get("source_path")
    if not source_path:
        logging.error(f"'source_path' is required. Skipping item: {item_name}.")
        return False
    df_arrows_edges = collect_arrows_edge_data(config)
    if df_arrows_edges is not None:
        #print(f"df_arrows_edges: {df_arrows_edges}")
        logging.info(f"Successfully processed {item_name}")
        return df_arrows_edges
    else:
        return False