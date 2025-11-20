from jsonpath_ng.ext.parser import parse as jpng_parse
import pandas as pd
import requests
import argparse
import logging
import json
import sys
import os

# global requests Session object
API_SESSION = requests.Session() 

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def connect_graphs(graph_a: str, match_a: str, graph_b: str, match_b: str, edge_kind: str, output_path: str) -> None:
    logging.info(f"Correlating {graph_a} and {graph_b}.")

    try:
        with open(graph_a, 'r') as f:
            graph_a_data = json.load(f)
        with open(graph_b, 'r') as f:
            graph_b_data = json.load(f)

        # normalize data
        df1 = pd.json_normalize(graph_a_data['graph']['nodes'])
        df2 = pd.json_normalize(graph_b_data['graph']['nodes'])

        # Clean Keys (String conversion + Trim whitespace)
        match_a_path = f'properties.{match_a}'
        match_b_path = f'properties.{match_b}'
        df1[match_a_path] = df1[match_a_path].astype(str).str.strip()
        df2[match_b_path] = df2[match_b_path].astype(str).str.strip()

        # Select relevant columns
        df1_subset = df1[['id', match_a_path]]
        df2_subset = df2[['id', match_b_path]]

        # Perform Outer Merge
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

        connected_graph = {
            "graph": {
                "edges": [                    
                ]
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

        # write output
        with open(output_path, 'w') as f:
            json.dump(connected_graph, f, indent=4)
            logging.info(f"Success! Output written to: {output_path}")
        
        # todo: dump this to a summary.json file or a central log file
        logging.info(f"Outputting processing_report summary:\n {json.dumps(processing_report, indent=4)}")        
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

def read_config_file(file_path):
    """
    Reads a JSON file and returns its content.
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

def call_rest_api(config):
    """
    Calls a REST API using the provided configuration and session.
    """
    request_url = config.get('source_url')
    request_auth_token = config.get('source_auth_token')
    source_auth_type = config.get('source_auth_type')

    req_headers = {"Accept": "application/json"}
    
    if source_auth_type == "bearer-token" and request_auth_token:
        req_headers["Authorization"] = f"Bearer {request_auth_token}"
    
    try:
        # use the global session for connection pooling - is this necessary?
        response = API_SESSION.get(request_url, headers=req_headers, timeout=30)
        response.raise_for_status()
        json_response = response.json()
        return json_response

    except requests.exceptions.RequestException as e:
        logging.error(f"[API ERROR] Failed to fetch {request_url}: {e}")
        return None
    except json.JSONDecodeError:
        logging.error(f"[API ERROR] Failed to decode JSON response from {request_url}.")
        # response should be defined here, as raise_for_status() and .json() failed
        # check if response is available before accessing .text
        if 'response' in locals() and hasattr(response, 'text'):
             logging.error(f"Response text: {response.text[:200]}...")
        else:
             logging.error("Response object was not available for text logging.")
        return None

def transform_node(input_object: pd.DataFrame, config: dict, source_kind: str):
    """
    Transforms a DataFrame into a list of node dictionaries.
    """
    column_mapping = config.get('column_mapping', {})
    target_columns = config.get('output_columns', [])    
    item_kind = config['item_kind']
    id_location = config['id_location']

    #logging.debug(f"id_location: {id_location}") 
    #logging.debug(f"target_columns: {target_columns}")

    df_renamed = input_object.rename(columns=column_mapping)
    valid_cols = [col for col in target_columns if col in df_renamed.columns]

    nan_string = "NULL"
    df_transformed = (
        df_renamed
        [valid_cols]
        .fillna(nan_string)
        .copy()
    )

    # convert dataframe to a dictionary
    records = df_transformed.to_dict('records')

    #logging.debug(f"records: {records}") 

    # construct node objects from transformed dataframe
    node_data = [
        {
            "id": row[id_location],
            "kinds": [item_kind, source_kind],
            "properties": row 
        }
        for row in records
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
        try:
            config_list = read_config_file(args.config)
            logging.info(f"Successfully read config from: {args.config}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(e)
            sys.exit(1)
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            sys.exit(1)      
            
        for config in config_list:
            item_name = config.get('item_name', 'Unknown Item')
            item_type = config.get('item_type')
            logging.info(f"Processing Item: {item_name} (Type: {item_type})")

            # validation
            source_type = config.get('source_type')
            if source_type == "url":
                if not config.get('source_url'):
                    logging.error(f"'source_url' is required for source_type='url' (Ref: {item_name}). Skipping.")
                    continue

                if config.get('source_auth_type') == "bearer-token" and not config.get('source_auth_token'):
                    logging.error(f"'source_auth_token' is required for bearer-token auth (Ref: {item_name}). Skipping.")
                    continue

                # retrieve data from API endpoint defined in tranformation (config)
                api_response = call_rest_api(config)

                #logging.debug(f"api_response: {api_response}") 
                
                if api_response is None:
                    logging.warning(f"Skipping item {item_name} due to failed API response.")
                    continue

                # retrieve the root data element
                data_root_element = config.get('data_root')
                if not data_root_element:
                    logging.error(f"'data_root' element is missing for item {item_name}. Skipping.")
                    continue
                    
                jsonpath_expression = jpng_parse(f'$..{data_root_element}')
                path_matches = jsonpath_expression.find(api_response)
                
                if not path_matches:
                    logging.error(f"Could not find data root element: {data_root_element} for item {item_name}. Skipping.")
                    continue

                first_match = path_matches[0]
                data_object = first_match.value

                #logging.debug(f"data_object: {data_object}") 
                
                # todo: update execution to resume here after retrieving data from source
                try:
                    # Normalizing the JSON data into a flat DataFrame
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

            # todo: add logic for 'json_file' and 'csv_file' here
            elif source_type != "url":
                logging.warning(f"Source type '{source_type}' is not yet implemented. Skipping item {item_name}.")
        
        # todo: add output controls
        #logging.info("Processing complete. Dumping graph to stdout:") 
        #json.dump(graph_structure, sys.stdout, indent=4)    

        output_file = args.output
        if output_file:
            logging.info(f"Writing graph to output file: {output_file}")
            try:      
                with open(output_file, 'w') as f:
                    json.dump(graph_structure, f, indent=4)         
                logging.info(f"Wrote graph to {output_file}")
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
