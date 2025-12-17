from jsonpath_ng import parse as jsonpath_parse
from typing import Any, Dict, List, Optional
from requests.adapters import HTTPAdapter
from json.decoder import JSONDecodeError
from urllib3.util.retry import Retry
import pandas as pd
import argparse
import requests
import logging
import getpass
import json
import sys
import os

# import collector modules
from collector_modules.ldap_collector import collect_ldap_data
from collector_modules.http_collector import collect_http_data
from collector_modules.csv_collector import collect_csv_data
from collector_modules.json_collector import collect_json_data

# configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# configure global session with retries
API_SESSION = requests.Session()
retry_strategy = Retry(
    total=3,                # Retry up to 3 times
    backoff_factor=1,       # Wait 1s, then 2s, then 4s between retries
    status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP codes
)
API_SESSION.mount("https://", HTTPAdapter(max_retries=retry_strategy))
API_SESSION.mount("http://", HTTPAdapter(max_retries=retry_strategy))

def get_nested(row: pd.Series, dotted_path: str) -> Any:
    """
    Resolve a dotted path relative to a row. Handles dicts inside cells.
    Example: 'details.idp_sso_uri' where row['details'] is a dict.
    """
    # If the column already exists (because upstream flattening created it), just use it.
    if dotted_path in row.index:
        return row[dotted_path]

    current: Any = row
    for part in dotted_path.split('.'):
        if isinstance(current, pd.Series):
            # Look up as a top-level column first.
            if part in current.index:
                current = current[part]
            else:
                # If the entire row doesn't have that column, cannot descend here.
                return None
        elif isinstance(current, dict):
            current = current.get(part, None)
        else:
            # We hit a non-dict and non-Series object; cannot traverse further.
            return None

        if current is None:
            return None

    return current

def connect_graphs(graph_a: str, root_a: str,  id_a:str, match_a: str, graph_b: str, root_b: str, id_b: str, match_b: str, edge_kind: str, output_path: str) -> bool:
    """
    Loads the JSON from two graph files and correlates the data using the specified matching fields.
    """
    def load_json(path: str) -> Any:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logging.error(f"File not found: {path}")
            raise
        except JSONDecodeError as e:
            logging.error(f"Invalid JSON in {path}: {e}")
            raise

    def get_jsonpath_single(obj: Any, jsonpath_expr_str: str) -> Optional[Any]:
        """
        Evaluate a JSONPath expression against a JSON-like object and return a single result.

        - Parses `jsonpath_expr_str` and searches `obj`.
        - Returns the first match's value if one or more matches exist.
        - Returns None if no matches exist.
        - Logs a warning if multiple matches are found.
        - Logs and raises if the JSONPath expression is invalid.

        Parameters
        ----------
        obj : Any
            The JSON-like object (dict/list) to query.
        jsonpath_expr_str : str
            The JSONPath expression string.

        Returns
        -------
        Optional[Any]
            The value of the first match, or None if no matches.
        """
        try:
            expr = jsonpath_parse(jsonpath_expr_str)
        except Exception as e:
            logging.error(f"Invalid JSONPath expression '{jsonpath_expr_str}': {e}")
            raise
        matches = expr.find(obj)
        if not matches:
            return None
        return matches[0].value

    def load_roots_with_jsonpath(graph_a: str, graph_b: str, root_a: str, root_b: str) -> tuple[Any, Any]:
        graph_a_data = load_json(graph_a)
        graph_b_data = load_json(graph_b)

        # $..foo means recursive descent for key 'foo' anywhere in the JSON
        expr_a = f"$..{root_a}"
        expr_b = f"$..{root_b}"

        data_object_a = get_jsonpath_single(graph_a_data, expr_a)
        if data_object_a is None:
            logging.error(f"Could not find data root element: '{root_a}' in {graph_a}")
            raise KeyError(f"Root '{root_a}' not found")

        data_object_b = get_jsonpath_single(graph_b_data, expr_b)
        if data_object_b is None:
            logging.error(f"Could not find data root element: '{root_b}' in {graph_b}")
            raise KeyError(f"Root '{root_b}' not found")

        return data_object_a, data_object_b

    logging.info(f"Correlating {graph_a} (root: {root_a}) and {graph_b} (root: {root_b}) using keys '{match_a}' and '{match_b}'.")

    try:
        data_object_a, data_object_b = load_roots_with_jsonpath(graph_a, graph_b, root_a, root_b)
        
        # normalize data
        df1 = pd.json_normalize(data_object_a)
        df2 = pd.json_normalize(data_object_b)

        # drop rows that have NaN values in the ID or match column
        df1 = df1.dropna(axis=0, subset=[id_a, match_a])
        df2 = df2.dropna(axis=0, subset=[id_b, match_b])

        # select relevant columns and perform string cleaning (stripping/case) 
        # should this be changed to uppercase? i think BH normalizes to upper
        df1[match_a] = df1[match_a].astype(str).str.strip().str.lower()
        df2[match_b] = df2[match_b].astype(str).str.strip().str.lower()

        df1_subset = df1[[id_a, match_a]].copy()
        df2_subset = df2[[id_b, match_b]].copy()
        
        #print(f"df1_subset: {df1_subset}")
        #print("df2_subset: {df2_subset}")
    
        # perform outer merge using the match columns as our key
        merged_df = pd.merge(
            df1_subset,
            df2_subset,
            left_on=match_a,
            right_on=match_b,
            how='outer',
            indicator=True            
        )
        #print("merged_df: {merged_df}")

        # Matched nodes only
        success_df = merged_df[merged_df['_merge'] == 'both'].copy()
        #print(f"success_df: {success_df}")

        success_output = success_df.rename(columns={id_a: 'start_value', id_b: 'end_value'})[['start_value', 'end_value']]

        # Template graph structure
        connected_graph = {
            "graph": {
                "edges": []
            }
        }

        # Construct edge objects from transformed dataframe
        edges = [
            {
                "kind": edge_kind,
                "start": {
                    "value": row['start_value']
                },
                "end": {
                    "value": row['end_value']
                }
            }
            for row in success_output[['start_value', 'end_value']].to_dict('records')
        ]

        connected_graph['graph']['edges'].extend(edges)

        # Write output
        with open(output_path, 'w') as f:
            json.dump(connected_graph, f, indent=4)
            logging.info(f"Success! Output written to: {output_path}")
        return True

    except KeyError as e:
        # A KeyError now likely means the dot-path itself is invalid or 'id' column is missing
        logging.error(f"Key error during processing (check your dot-path property names: {match_a} or {match_b}, or confirm 'id' is available in the root data): {e}")
        return False
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return False
    except Exception as e:
        logging.error(f"Connect graphs: An unexpected error occurred: {e}")
        return False

def transform_node(input_object: pd.DataFrame, config: dict, source_kind: str):
    """
    Transforms a DataFrame into a list of node dictionaries.
    Supports dot-paths in column_mapping and id_location to resolve nested objects.
    """
    column_mapping: Dict[str, str] = config.get('column_mapping', {})
    target_columns: List[str] = config.get('output_columns', [])
    item_kind: str = config['item_kind']
    id_location: str = config['id_location']
    
    df = input_object.copy()

    # We only need to materialize a column for a source key if it's dotted (contains '.')
    # or if the DF doesn't already have that column name.
    for source_path, target_name in column_mapping.items():
        needs_materialization = ('.' in source_path) or (source_path not in df.columns)
        if needs_materialization:
            # Materialize source_path into a temporary column so .rename() can pick it up.
            df[source_path] = df.apply(lambda row: get_nested(row, source_path), axis=1)
            
    df_renamed = df.rename(columns=column_mapping)
    #print(f"df_renamed: {df_renamed}")

    # Filter to requested target columns (post-rename names)
    valid_cols = [col for col in target_columns if col in df_renamed.columns]
    # todo: check on the important fields and drop rows that are missing values we need
    nan_string = config.get('nan_string', 'NULL')

    df_transformed = (
        df_renamed[valid_cols]
        .fillna(nan_string)
        .astype(str)
        .copy()
    )

    # resolve id with dot-path support
    if id_location in df_transformed.columns:
        id_series = df_renamed[id_location]
    else:
        # Create a temporary id column if id_location is dotted/nested
        id_series = df.apply(lambda row: get_nested(row, id_location), axis=1)

    records = df_transformed.to_dict('records')
    #print(f"records: {records}")

    # Convert the id_series to a list for zipping
    id_list = id_series.astype(str).tolist() # Convert to list of strings for safety

    # Combine the IDs and the properties for final structure
    # Use zip() to iterate through IDs and property dictionaries simultaneously
    node_data = [
        {
            "id": node_id,                       # Use the extracted ID from id_list
            "kinds": [item_kind, source_kind],
            "properties": properties_dict
        }
        for node_id, properties_dict in zip(id_list, records)
    ]

    return node_data

def transform_edge(input_object: pd.DataFrame, config: dict):
    """
    Transforms a DataFrame into a list of edge dictionaries.
    Supports dot-paths in column_mapping, target_column, and source_column 
    to resolve nested objects.
    """
    df = input_object.copy()

    column_mapping: Dict[str, str] = config.get('column_mapping', {})
    
    source_col = config['source_column']
    target_col = config['target_column']
    
    source_paths = set(column_mapping.keys())
    source_paths.add(source_col)
    source_paths.add(target_col)

    # Identify all source paths that might be dotted and need materializing.
    # This includes keys in column_mapping, source_column, and target_column.
    for source_path in source_paths:
        needs_materialization = ('.' in source_path) or (source_path not in df.columns)
        if needs_materialization:
            # Materialize source_path into a temporary column
            df[source_path] = df.apply(lambda row: get_nested(row, source_path), axis=1)

    # remap columns (now that dotted source paths are materialized)
    df.rename(columns=column_mapping, inplace=True)
    
    # Check for multi-valued target node
    if config.get('target_is_multi_valued', False):
        # explode the column to create a new row in the dataframe for each value
        df = df.explode(target_col)
    
    # no null start, end nodes (using the materialized column names)
    df = df[
        (df[target_col].astype(str) != "None") & 
        (df[target_col].astype(str) != "null") & 
        (df[source_col].astype(str) != "None") &
        (df[source_col].astype(str) != "null")
    ]

    ## todo: add logic to handle situations where no ouput_columns are provided - pass an don't modify the df

    # we may not want everything, so filter the columns
    target_columns: List[str] = config.get('output_columns', [])
    if target_columns:
        valid_cols = [col for col in target_columns if col in df.columns]
        df = df[valid_cols]

    # vectorized start_id calculation
    df['start_id'] = df[source_col].astype(str).str.strip()

    # vectorized end_id calculation, depending on the 'target_is_multi_valued' control property
    if config.get('target_is_multi_valued', False):
        target_column_id = config['target_column_id']
        # If target_col contains dicts, extract the nested ID. Otherwise, use the value directly.
        df['end_id'] = df[target_col].apply(
            lambda x: str(x.get(target_column_id)).strip() if isinstance(x, dict) and x.get(target_column_id) is not None else str(x).strip()
        )
    else:
        df['end_id'] = df[target_col].astype(str).str.strip()
    
    # vectorized edge_kind calculation, depending on the 'edge_type' control property
    edge_type = config['edge_type']
    if edge_type == 'from_column':
        edge_object = df[target_col]
        edge_col_id = config['edge_column_id']
        # If the target is a dict, extract the nested edge kind. Otherwise, use the value directly.
        df['edge_kind'] = edge_object.apply(
            lambda x: x.get(edge_col_id) if isinstance(x, dict) and x.get(edge_col_id) is not None else x
        ).astype(str).str.strip()
    else:
        df['edge_kind'] = str(config['edge_name']).strip()
        
    # construct edge objects from transformed dataframe
    edge_data = [
        {
            "kind": row['edge_kind'],
            "start": {"value": row['start_id']},
            "end": {"value": row['end_id']}
            # todo: add properties?
        }
        for row in df[['edge_kind', 'start_id', 'end_id']].to_dict('records')
    ]
    
    return edge_data

def read_config_file(file_path):
    """
    Reads a JSON file and returns its content, hopefully.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Error: The file '{file_path}' was not found.")
        
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Error decoding JSON in '{file_path}': {e.msg}", e.doc, e.pos)

    if not isinstance(data, list):
        logging.warning(f"The file '{file_path}' content is not a list, but a {type(data).__name__}. Treating as single config.")
        return [data] if isinstance(data, dict) else []
        
    return data

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

def process_http_source(config):
    item_name = config.get('item_name', 'NA')
    if not config.get('item_type'):
        logging.error(f"'item_type' is required. Skipping item: {item_name}.")
        return False
    item_type = config.get('item_type')    
    
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
    item_name = config.get('item_name', 'NA')
    if not config.get('item_type'):
        logging.error(f"'item_type' is required. Skipping item: {item_name}.")
        return False
    # unused currently, does this have a purpose?
    item_type = config.get('item_type')     
    ldap_password = getpass.getpass("LDAP Bind Password: ")
    # retrieve data from ldap
    ldap_data = collect_ldap_data(config, ldap_password)
    if ldap_data is None:
        logging.warning(f"Skipping item {item_name} due to failed LDAP connection/search.")
        return False
    # something was returned, point data_object to it for processing
    data_object = ldap_data
    ## todo: add check to validate data_object
    try:
        # sanitize the data to prevent unintended data conversions during the pd.json_normalize operation
        # without this, integer values can be converted into floats
        clean_data_object = replace_none_with_string_null(data_object)
        # flatten JSON
        #df = pd.json_normalize(data_object)
        df = pd.json_normalize(clean_data_object)
        return df
    except Exception as e:
        logging.error(f"Failed to normalize data for item {item_name}: {e}. Skipping.")
        return False

def process_csv_source(config):
    item_name = config.get('item_name', 'NA')
    if not config.get('item_type'):
        logging.error(f"'item_type' is required. Skipping item: {item_name}.")
        return False
    # todo: unused currently, does this have a purpose?
    item_type = config.get('item_type')     
    csv_data = collect_csv_data(config)
    if csv_data is None:
        logging.warning(f"Skipping item {item_name} due to failed parsing of input file.")
        return False
    # something was returned, point data_object to it for processing
    #print(f"csv_data: {csv_data}")
    df = csv_data  
    return df

def process_json_source(config):
    item_name = config.get('item_name', 'NA')
    if not config.get('item_type'):
        logging.error(f"'item_type' is required. Skipping item: {item_name}.")
        return False
    # unused currently, does this have a purpose?
    item_type = config.get('item_type')     
    json_data = collect_json_data(config)
    if json_data is None:
        logging.warning(f"Skipping item {item_name} due to failed parsing of input file.")
        return False
    # something was returned, point data_object to it for processing
    #print(f"json_data: {json_data}")
    df = json_data       
    return df

def generate_static_node(config: dict) -> Optional[pd.DataFrame]:
    """
    Creates a single-row DataFrame from static configuration.
    Serializes 'static_id', 'static_name', 'static_kind', and all keys
    from the 'properties' dictionary directly into DataFrame columns.

    Parameters:
    - config: The edge configuration dictionary that contains the static data to map.    
    """
    node_id = config.get('static_id', 'NA')
    node_name = config.get('static_name', 'NA')    
    # default to an empty dict if missing to avoid errors during unpacking
    node_properties = config.get('properties', {}) 

    '''
    # base data dictionary
    base_data = {
        "id": node_id,
        "name": node_name,
        "kind": node_kind
    }
    '''

    # base data dictionary
    base_data = {
        "id": node_id,
        "name": node_name
    }
    
    # use the dictionary unpacking operator (**) to merge properties into the base data dictionary.
    data_row = {
        **base_data,
        **node_properties
    }

    # create the dataframe from a list containing the single data dictionary
    data_series = [data_row]
    df = pd.DataFrame(data_series)
    # return dataframe for transformation processing
    return df

def generate_static_edge(config):
    """
    Prepares a DataFrame to be processed by transform_edge by collecting static values from the config dictionary.

    Parameters:
    - config: The edge configuration dictionary that contains the static data to map.
    """    
    edge_name = config.get('edge_name', 'NA')
    start_id = config.get('start_id', 'NA')
    end_id = config.get('end_id', 'NA')
    source_column = config.get('source_column', 'NA')
    target_column = config.get('target_column', 'NA')
    # setup a dictionary with the details that the tranformation method expects
    # if nothing is getting changed, this could all just be passed by the config dict and this whole call can be avoided. 
    # but there may be some use for this level of control - leaving as the config values may be streamlined soon
    base_data = [{
        "start_id": start_id,
        "end_id": end_id,
        "edge_type": "static",
        "edge_name": edge_name,
        "source_column": source_column,
        "target_column": target_column
    }]
    # create dataframe
    df = pd.DataFrame(base_data)
    # return dataframe for transformation processing
    return df

def prepare_static_start_edge_data(df: pd.DataFrame, config: dict):
    """
    Prepares a DataFrame for transform_edge by injecting static ID values.

    Parameters:
    - df: The DataFrame returned by a collector (contains the dynamic start node data).
    - config: The edge configuration dictionary.
    """
        
    edge_name = config.get('edge_name', 'DEFAULT_EDGE')
    static_start_id = config.get('start_id') # The static ID value
    target_column = config.get('target_column') # Column holding dynamic end ID
    
    # validation checks
    if target_column not in df.columns or static_start_id is None:
        logging.error(f"Missing required data or config for edge '{edge_name}'.")
        return False
    
    # the 'transform_edge' function expects the data to be in the 'source_column' and 'target_column' before the start/end ID calculation.
    # Assign the static ID to the column defined as the 'source_column' in the config.
    df[config['source_column']] = str(static_start_id).strip()

    # The 'target_column' already holds the dynamic ID, so no change is needed there.
    # inject the static edge name into the config for transform_edge
    config['edge_name'] = edge_name
    config['edge_type'] = 'static'
    
    # return the prepared dataframe
    return df

def prepare_static_end_edge_data(df: pd.DataFrame, config: dict):
    """
    Prepares a DataFrame for transform_edge by injecting static ID values.

    Parameters:
    - df: The DataFrame returned by a collector (contains the dynamic start node data).
    - config: The edge configuration dictionary.
    """
        
    edge_name = config.get('edge_name', 'DEFAULT_EDGE')
    source_column = config.get('source_column') # Column holding dynamic start ID
    static_end_id = config.get('end_id') # The static ID value

    # validation checks
    if source_column not in df.columns or static_end_id is None:
        logging.error(f"Missing required data or config for edge '{edge_name}'.")
        return pd.DataFrame() # Return empty dataframe on failure
    
    # the 'transform_edge' function expects the data to be in the 'source_column' and 'target_column' before the start/end ID calculation.
    # Assign the static ID to the column defined as the 'target_column' in the config.
    df[config['target_column']] = str(static_end_id).strip()

    # The 'source_column' already holds the dynamic ID, so no change is needed there.
    # inject the static edge name into the config for transform_edge
    config['edge_name'] = edge_name
    config['edge_type'] = 'static'
    
    # return the prepared dataframe
    return df

def generate_hybrid_edge(config):
    """
    Generates a hybrid edge DataFrame by dynamically selecting a data source
    and applying the appropriate transformation.
    """
    edge_name = config.get('edge_name', 'NA')
    dynamic_element = config.get('dynamic_element')
    df = None # Initialize DataFrame to ensure it's defined
    
    # Select the configuration key that holds the source type based on 'dynamic_element'
    if dynamic_element == "start":
        source_type_key = 'start_source_type'
    elif dynamic_element in (None, "end"): # Assuming default is 'end' if dynamic_element is not 'start'
        source_type_key = 'end_source_type'
        # start_id only seems used in this branch, but is otherwise unused.
        # start_id = config.get('start_id', 'NA')
    else:
        # Handle unexpected dynamic_element value gracefully
        raise ValueError(f"Invalid dynamic_element value: {dynamic_element}. Must be 'start', 'end', or None.")

    source_type = config.get(source_type_key)

    # dictionary mapping for source processing functions
    # todo: am i missing static here?
    source_processors = {
        "url": process_http_source,
        "ldap": process_ldap_source,
        "csv": process_csv_source,
        "json": process_json_source,
    }
    
    if source_type in source_processors:          
        # Call the corresponding function from the dictionary map
        df = source_processors[source_type](config)
    else:
        raise ValueError(f"Unsupported source_type: {source_type} in configuration key '{source_type_key}'")

    transformed_df = None

    if dynamic_element == "start":
        # Note: The original code used 'prepare_static_end_edge_data' for dynamic_element == "start"
        transformed_df = prepare_static_end_edge_data(df, config)
    elif dynamic_element in ("end", None): # Assuming 'end' or no dynamic_element uses the static_start logic
        # Note: The original code used 'prepare_static_start_edge_data' for all other cases
        transformed_df = prepare_static_start_edge_data(df, config)
    
    # source_column = config.get('source_column', 'NA')
    # target_column = config.get('target_column', 'NA')

    return transformed_df

# main execution
def main():
    parser = argparse.ArgumentParser(description="A versatile data pipeline engine that ingests information from diverse external sources and transforms the extracted node and edge data into the BloodHound OpenGraph format.")
    
    # common arguments
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument("--operation", required=True, type=str, choices=["collect", "connect"], help="Operation to complete.")
    general_group.add_argument("--output", required=True, type=str, help="Output file path for graph JSON", default="output_graph.json")

    # arguments for all operations
    collect_group = parser.add_argument_group("Collect Options")
    collect_group.add_argument("--source-kind", type=str, help="The 'source_kind' to use for nodes in the graph.")
    collect_group.add_argument("--config", type=str, help="The path to the collection config file.")
    
    # arguments for connect operations
    connect_group = parser.add_argument_group("Connect Options")
    connect_group.add_argument("--graphA", type=str, help="Graph containing Start nodes.")
    connect_group.add_argument("--rootA", type=str, help="Element containing the root of the node data (ex: nodes).")
    connect_group.add_argument("--idA", type=str, help="Element containing the field to use as the start node ID (ex: id) from Graph A.")
    connect_group.add_argument("--matchA", type=str, help="Element containing the field to match on in Graph A.")
    
    connect_group.add_argument("--graphB", type=str, help="Graph containing End nodes.")
    connect_group.add_argument("--rootB", type=str, help="Element containing the field to match on in Graph B.")
    connect_group.add_argument("--idB", type=str, help="Element containing the field to use as the end node ID (ex: id) from Graph B.")
    connect_group.add_argument("--matchB", type=str, help="Element containing the field to match on in Graph B.")
    
    connect_group.add_argument("--edge-kind", type=str, help="Kind value to use when generating connection edges (ex: MapsTo).")

    # arguments for upload operations
    #upload_group = parser.add_argument_group("Upload Options")
    #upload_group.add_argument("--file", type=str, help="Graph JSON to upload")
    #upload_group.add_argument("--base-url", type=str, help="BH base URL")

    args = parser.parse_args()

    if pd is None:
        logging.error("Pandas is not installed. Run: pip install pandas")
        sys.exit(1)

    source_kind = args.source_kind
    graph_structure = {
        "metadata": { "source_kind": source_kind }, 
        "graph": {
            "nodes": [],
            "edges": []
        }
    }   

    operation = args.operation
    if operation == "collect":       
        # first thing we need to do is read the collection definitions config file 
        try:
            config_list = read_config_file(args.config)
            logging.info(f"Successfully read config from: {args.config}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(e)
            sys.exit(1)
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            sys.exit(1)      
                   
        # parse through each item in the config file
        for config in config_list:
            item_name = config.get('item_name', 'NA')
            df = None # Initialize df

            if not config.get('item_type'):
                logging.error(f"'item_type' is required. Skipping item: {item_name}.")
                continue
            
            item_type = config.get('item_type')
            logging.info(f"Processing Item: {item_name} (Type: {item_type})")

            source_processors = {
                "url": process_http_source,
                "ldap": process_ldap_source,
                "csv": process_csv_source,
                "json": process_json_source,
                "static": generate_static_node, # todo: does this naming make sense anymore?
            }

            item_type_direct_processors = {
                "static_edge": generate_static_edge,
                "hybrid_edge": generate_hybrid_edge,
            }

            # handle special item types that process directly (e.g., static_edge)
            if item_type in item_type_direct_processors:                
                df = item_type_direct_processors[item_type](config)
                
            # handle 'node' and 'edge' items that rely on 'source_type' lookup
            elif item_type in ("node", "edge"):
                if not config.get('source_type'):
                    logging.error(f"'source_type' is required. Skipping item: {item_name}.")
                    continue
                    
                source_type = config.get('source_type')
                
                # Use the source_processors dictionary for the dynamic lookup
                if source_type in source_processors:
                    df = source_processors[source_type](config)
                else:
                    logging.warning(f"Source type '{source_type}' is not yet implemented. Skipping item {item_name}.")
                    continue
                    
            # all other unknown item types
            else:
                logging.warning(f"Item type '{item_type}' is not yet implemented. Skipping item {item_name}.")
                continue
            
            if df is False:
                logging.error("DataFrame object is invalid. Collection likely failed. Exiting.")
                sys.exit(1)

            # dictionary of transform functions
            TRANSFORMERS = {
                'node': transform_node,
                'edge': transform_edge,
                'static_edge': transform_edge,
                'hybrid_edge': transform_edge
            }

            # transform and append using dispatch dictionary
            transformer = TRANSFORMERS.get(item_type)
            if transformer:
                # for nodes we'll pass the source_kind value, but we don't need it for edges
                # todo: consider refactoring transformation logic to take advantage of this
                if item_type == 'node':
                    transformed_data = transformer(df, config, source_kind)
                else:
                    transformed_data = transformer(df, config)

                ## todo: confirm that transformed_data has a value
                # append 'transformed_data' to the appropriate graph element (nodes or edges)
                target_list = 'nodes' if item_type == 'node' else 'edges'
                graph_structure['graph'][target_list].extend(transformed_data)
                logging.info(f"Successfully processed {len(transformed_data)} {item_type}s.")
            else:
                logging.error(f"Unable to resolve transformer function for type: '{item_type}'. Skipping.")
                            
        # todo: add output controls
        output_file = args.output
        if output_file:
            logging.info(f"Writing graph to output file: {output_file}")
            try:      
                with open(output_file, 'w') as f:
                    json.dump(graph_structure, f, indent=4, default=str)         
                logging.info(f"Successfully Wrote graph to {output_file}")
            except Exception as e: 
                logging.error(f"Failed to write output file: {output_file}. Error: {e}")

    elif operation == "connect":
        # graph a properties
        graph_a = args.graphA
        root_a = args.rootA
        id_a = args.idA
        match_a = args.matchA
        # graph b properties
        graph_b = args.graphB
        root_b = args.rootB
        id_b = args.idB
        match_b = args.matchB
        # connecting edge kind
        edge_kind = args.edge_kind
        if edge_kind is None:
            logging.error("The '--edge-kind' argument is required with the 'connect' operation.")
            sys.exit(1)
        output_file = args.output
        if output_file:
            if connect_graphs(graph_a, root_a, id_a, match_a, graph_b, root_b, id_b, match_b, edge_kind, output_file):
                logging.info(f"Successfully connected graphs with {edge_kind} edge kind.")
            else:
                logging.error(f"Failed to connect graph A ({graph_a}) to graph B ({graph_b})")
                sys.exit(1)
        else:
            logging.error("Output file is missing! Unable to complete graph connection.")
            sys.exit(1)
    else:
        logging.error("Unrecognized operation! How'd you even get here??")
        sys.exit(1)
    
    logging.info("Done.")

if __name__ == '__main__':
    main()