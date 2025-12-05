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
        
        #print("df1_subset:")
        #print(df1_subset)
        #print("df2_subset:")
        #print(df2_subset)
    
        # perform outer merge using the match columns as our key
        merged_df = pd.merge(
            df1_subset,
            df2_subset,
            left_on=match_a,
            right_on=match_b,
            how='outer',
            indicator=True            
        )
        #print("merged_df:")
        #print(merged_df)

        # Matched nodes only
        success_df = merged_df[merged_df['_merge'] == 'both'].copy()
        #print("success_df:")
        #print(success_df)

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

    # --- create columns for dotted source paths -----------------------------
    # We only need to materialize a column for a source key if it's dotted (contains '.')
    # or if the DF doesn't already have that column name.
    df = input_object.copy()

    for source_path, target_name in column_mapping.items():
        needs_materialization = ('.' in source_path) or (source_path not in df.columns)
        if needs_materialization:
            # Materialize source_path into a temporary column so .rename() can pick it up.
            df[source_path] = df.apply(lambda row: get_nested(row, source_path), axis=1)

    df_renamed = df.rename(columns=column_mapping)

    # Filter to requested target columns (post-rename names)
    valid_cols = [col for col in target_columns if col in df_renamed.columns]

    # todo: check on the important fields and drop rows that are missing values we need
    nan_string = config.get('nan_string', 'NULL')

    df_transformed = (
        df_renamed[valid_cols]
        .fillna(nan_string)
        .copy()
    )

    # Resolve id (support dot-path too)
    if id_location in df_transformed.columns:
        id_series = df_renamed[id_location]
    else:
        # Create a temporary id column if id_location is dotted/nested
        id_series = df.apply(lambda row: get_nested(row, id_location), axis=1)

    records = df_transformed.to_dict('records')

    node_data = [
        {
            "id": str(id_series.iloc[i]).strip() if pd.notna(id_series.iloc[i]) else nan_string,
            "kinds": [item_kind, source_kind],
            "properties": records[i]
        }
        for i in range(len(records))
    ]

    return node_data

def transform_edge(input_object: pd.DataFrame, config: dict):
    """
    Transforms a DataFrame into a list of edge dictionaries.
    Supports dot-paths in column_mapping, target_column, and source_column 
    to resolve nested objects.
    """
    df = input_object.copy()

    # --- create columns for dotted source paths -----------------------------
    column_mapping: Dict[str, str] = config.get('column_mapping', {})
    
    # Identify all source paths that might be dotted and need materializing.
    # This includes keys in column_mapping, source_column, and target_column.
    source_col = config['source_column']
    target_col = config['target_column']
    
    source_paths = set(column_mapping.keys())
    source_paths.add(source_col)
    source_paths.add(target_col)

    for source_path in source_paths:
        needs_materialization = ('.' in source_path) or (source_path not in df.columns)
        if needs_materialization:
            # Materialize source_path into a temporary column
            df[source_path] = df.apply(lambda row: get_nested(row, source_path), axis=1)

    # --- your original flow continues ---------------------------------------
    
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
            # todo: add properties
        }
        for row in df[['edge_kind', 'start_id', 'end_id']].to_dict('records')
    ]
    
    return edge_data

def _transform_edge(input_object: pd.DataFrame, config: dict):
    """
    Transforms a DataFrame into a list of edge dictionaries.
    """
    # --- helpers -------------------------------------------------------------
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

    df = input_object.copy()

    # remap columns
    column_mapping = config.get('column_mapping', {})
    df.rename(columns=column_mapping, inplace=True)
    
    target_col = config['target_column']
    source_col = config['source_column']
    
    # check for multi-valued target node
    if config.get('target_is_multi_valued', False):
        # explode the column to create a new row in the dataframe for each value
        df = df.explode(target_col)
    
    # no null start, end nodes
    #print(df)
    df = df[
        (df[target_col] != "null") &  # target_col is not "null"
        (df[source_col] != "null")    # source_col is not "null"
    ]
    #print(df)

    # we may not want everything, so filter the columns
    target_columns = config.get('output_columns')
    if target_columns:
        valid_cols = [col for col in target_columns if col in df.columns]
        df = df[valid_cols]

    # vectorized start_id calculation
    df['start_id'] = df[source_col].astype(str)

    # vectorized end_id calculation, depending on the 'target_is_multi_valued' control property
    if config.get('target_is_multi_valued', False):
        target_column_id = config['target_column_id']
        df['end_id'] = df[target_col].apply(lambda x: str(x.get(target_column_id)) if isinstance(x, dict) else str(x))
    else:
        df['end_id'] = df[target_col].astype(str)
    
    # vectorized edge_kind calculation, depending on the 'edge_type' control property
    edge_type = config['edge_type']
    if edge_type == 'from_column':
        edge_object = df[config['target_column']]
        edge_col_id = config['edge_column_id']
        df['edge_kind'] = edge_object.apply(lambda x: x.get(edge_col_id) if isinstance(x, dict) else x)
    else:
        df['edge_kind'] = config['edge_name']
        
    # construct edge objects from transformed dataframe
    edge_data = [
        {
            "kind": row['edge_kind'],
            "start": {"value": row['start_id']},
            "end": {"value": row['end_id']}
            # todo: add properties
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

# dictionary of transform functions
TRANSFORMERS = {
    'node': transform_node,
    'edge': transform_edge
}

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
            item_name = config.get('item_name')
            item_type = config.get('item_type')

            logging.info(f"Processing Item: {item_name} (Type: {item_type})")

            if not config.get('source_type'):
                logging.error(f"'source_type' is required. Skipping.")
                continue

            source_type = config.get('source_type')
            if source_type == "url":
                # validation
                if not config.get('source_url'):
                    logging.error(f"'source_url' is required for source_type='url' (Ref: {item_name}). Skipping.")
                    continue

                if config.get('source_auth_type') == "bearer-token" and not config.get('source_auth_token'):
                    logging.error(f"'source_auth_token' is required for bearer-token auth (Ref: {item_name}). Skipping.")
                    continue

                # retrieve data from API endpoint defined in tranformation (config)
                api_response = collect_http_data(config, API_SESSION)

                # todo: add debug output control with additional debug statements
                #logging.debug(f"api_response: {api_response}") 
                
                if api_response is None:
                    logging.warning(f"Skipping item {item_name} due to failed API response.")
                    continue

                # retrieve the root data element
                data_root_element = config.get('data_root')
                if not data_root_element:
                    logging.error(f"'data_root' element is missing for item {item_name}. Skipping.")
                    continue
                    
                # create a jsonpath expression to find all matches for the data root element recursively             
                jsonpath_expression = jsonpath_parse(f'$..{data_root_element}')
                # check the API response for jsonpath_expression
                path_matches = jsonpath_expression.find(api_response)
                
                # no matches
                if not path_matches:
                    logging.error(f"Could not find data root element: {data_root_element} for item {item_name}. Skipping.")
                    continue

                first_match = path_matches[0]
                data_object = first_match.value
            elif source_type == "ldap":
                ldap_password = getpass.getpass("LDAP Bind Password: ")
                # retrieve data from ldap
                ldap_data = collect_ldap_data(config, ldap_password)
                if ldap_data is None:
                    logging.warning(f"Skipping item {item_name} due to failed LDAP connection/search.")
                    continue
                # something was returned, point data_object to it for processing
                data_object = ldap_data                 
            else:
                logging.warning(f"Source type '{source_type}' is not yet implemented. Skipping item {item_name}.")
                
            ## todo: add check to validate data_object
            try:
                # sanitize the data to prevent unintended data conversions during the pd.json_normalize operation
                # without this, integer values can be converted into floats
                clean_data_object = replace_none_with_string_null(data_object)
                # flatten JSON
                df = pd.json_normalize(clean_data_object)
                #df = pd.json_normalize(data_object)
            except Exception as e:
                logging.error(f"Failed to normalize data for item {item_name}: {e}. Skipping.")
                continue

            # transform and append using dispatch dictionary
            transformer = TRANSFORMERS.get(item_type)
            if transformer:
                # for nodes we'll pass the source_kind value, but we don't need it for edges
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
                logging.error(f"Unknown item_type '{item_type}' defined for item {item_name}. Skipping.")

        # todo: add output controls
        #logging.info("Processing complete. Dumping graph to stdout:") 
        #json.dump(graph_structure, sys.stdout, indent=4)    

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