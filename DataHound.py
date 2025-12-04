from jsonpath_ng.ext.parser import parse as jpng_parse
from typing import Any, Dict, List, Optional
from requests.adapters import HTTPAdapter
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

def connect_graphs(graph_a: str, match_a: str, graph_b: str, match_b: str, edge_kind: str, output_path: str) -> None:
    """
    Loads the JSON from two OG files and correlates the data using the specified matching fields.
    An OG JSON to connect matching nodes is generated, along with a summary of entries from either side without a match.
    """
    logging.info(f"Correlating {graph_a} and {graph_b}.")

    try:
        with open(graph_a, 'r') as f:
            graph_a_data = json.load(f)
        with open(graph_b, 'r') as f:
            graph_b_data = json.load(f)

        # normalize data        
        df1 = pd.json_normalize(graph_a_data['graph']['nodes'])
        df2 = pd.json_normalize(graph_b_data['graph']['nodes'])

        # clean keys (string conversion + trim whitespace)
        ## todo: change this so that it doesn't have to be under 'properties'
        match_a_path = f'properties.{match_a}'
        match_b_path = f'properties.{match_b}'
        df1[match_a_path] = df1[match_a_path].astype(str).str.strip()
        df2[match_b_path] = df2[match_b_path].astype(str).str.strip()

        # select relevant columns
        df1_subset = df1[['id', match_a_path]]
        df2_subset = df2[['id', match_b_path]]

        # perform outer merge using the matchA and matchB fields
        merged_df = pd.merge(
            df1_subset,
            df2_subset,
            left_on=match_a_path,
            right_on=match_b_path,
            how='outer',
            indicator=True
        )

        # matched nodes
        success_df = merged_df[merged_df['_merge'] == 'both'].copy()
        # remap column names - now success_output is what we want to use to build the graph
        success_output = success_df.rename(columns={'id_x': 'start_value', 'id_y': 'end_value'})[['start_value', 'end_value']]

        # failures (Graph A Orphans)
        grapha_fail_df = merged_df[merged_df['_merge'] == 'left_only'].copy()
        grapha_fail_output = grapha_fail_df.rename(columns={
            'id_x': 'failed_node_id',
            match_a_path: 'missing_lookup_key'
        })[['failed_node_id', 'missing_lookup_key']]

        # failures (Graph B Orphans)
        graphb_fail_df = merged_df[merged_df['_merge'] == 'right_only'].copy()
        graphb_fail_output = graphb_fail_df.rename(columns={
            'id_y': 'failed_node_id',
            match_b_path: 'missing_lookup_key'
        })[['failed_node_id', 'missing_lookup_key']]

        # template graph structure
        connected_graph = {
            "graph": {
                "edges": []
            }
        }

        # construct edge objects from transformed dataframe
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

        # write output
        with open(output_path, 'w') as f:
            json.dump(connected_graph, f, indent=4)
            logging.info(f"Success! Output written to: {output_path}")
        
        # report of errors and summary stats
        processing_report = {
            "summary": {
                "total_matches": len(success_output),
                "unmatched_graph_a": len(grapha_fail_output),
                "unmatched_graph_b": len(graphb_fail_output)
            },
            "records": {
                "unmatched_in_graph_a": grapha_fail_output.to_dict(orient='records'),
                "unmatched_in_graph_b": graphb_fail_output.to_dict(orient='records')             
            }            
        }
        # todo: dump this to a summary.json file or a central log file, the output gets long with real datasets
        #logging.info(f"Outputting processing_report summary:\n {json.dumps(processing_report, indent=4)}")
        return True

    except KeyError as e:
        logging.error(f"Key error during processing (check your property names): {e}")
        return True
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

    # --- create columns for dotted source paths -----------------------------
    # We only need to materialize a column for a source key if it's dotted (contains '.')
    # or if the DF doesn't already have that column name.
    df = input_object.copy()

    for source_path, target_name in column_mapping.items():
        needs_materialization = ('.' in source_path) or (source_path not in df.columns)
        if needs_materialization:
            # Materialize source_path into a temporary column so .rename() can pick it up.
            df[source_path] = df.apply(lambda row: get_nested(row, source_path), axis=1)

    # --- your original flow continues ---------------------------------------
    df_renamed = df.rename(columns=column_mapping)

    # Filter to requested target columns (post-rename names)
    valid_cols = [col for col in target_columns if col in df_renamed.columns]

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
    """
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
    
    # clean up NaN values that will break JSON
    replacement_string = "NULL" 
    df.fillna(replacement_string, inplace=True)
    
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
    connect_group.add_argument("--graphA", type=str, help="Graph containing Start nodes")
    connect_group.add_argument("--matchA", type=str, help="Element containing the field to match on in Graph A")
    connect_group.add_argument("--graphB", type=str, help="Graph containing End nodes")
    connect_group.add_argument("--matchB", type=str, help="Element containing the field to match on in Graph B")
    connect_group.add_argument("--edge-kind", type=str, help="Kind value to use when generating connection edges")

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
                jsonpath_expression = jpng_parse(f'$..{data_root_element}')
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
        
            try:
                # flatten JSON
                df = pd.json_normalize(data_object)
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
        graph_a = args.graphA
        match_a = args.matchA
        graph_b = args.graphB
        match_b = args.matchB
        edge_kind = args.edge_kind
        if edge_kind is None:
            logging.error("The '--edge-kind' argument is required with the 'connect' operation.")
            sys.exit(1)
        output_file = args.output
        if output_file:
            if connect_graphs(graph_a, match_a, graph_b, match_b, edge_kind, output_file):
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