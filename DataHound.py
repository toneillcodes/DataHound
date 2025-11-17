from jsonpath_ng.ext.parser import parse as jpng_parse
import pandas as pd
import requests
import argparse
import json
import sys
import os

# global requests Session object
API_SESSION = requests.Session() 

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
        print(f"Warning: The file '{file_path}' content is not a list, but a {type(data).__name__}. Treating as single config.")
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
        print(f"[API ERROR] Failed to fetch {request_url}: {e}")
        return None
    except json.JSONDecodeError:
        print(f"[API ERROR] Failed to decode JSON response from {request_url}.")
        print(f"Response text: {response.text[:200]}...")
        return None

def transform_node(input_object: pd.DataFrame, config: dict, base_kind: str):
    """
    Transforms a DataFrame into a list of node dictionaries.
    """
    column_mapping = config.get('column_mapping', {})
    target_columns = config.get('output_columns', [])    
    item_kind = config['item_kind']
    id_location = config['id_location']

    #print(f"[DEBUG] id_location: {id_location}")
    #print(f"[DEBUG] target_columns: {target_columns}")

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

    #print(f"[DEBUG] records: {records}")

    # construct node objects from transformed dataframe
    node_data = [
        {
            "id": row[id_location],
            "kinds": [item_kind, base_kind],
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
    parser.add_argument("base_kind", type=str, help="The base source_kind value to use for the graph.")
    parser.add_argument("input_file", type=str, help="The path to the transformation definitions file.")
    parser.add_argument("output_file", type=str, help="The path for the JSON output.") 
    
    args = parser.parse_args()

    try:
        config_list = read_config_file(args.input_file)
        print(f"[*] Successfully read config from: {args.input_file}")
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(e)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        sys.exit(1)

    base_kind = args.base_kind
    graph_structure = {
        "metadata": { "source_kind": base_kind }, 
        "graph": {
            "nodes": [],
            "edges": []
        }
    }

    for config in config_list:
        item_name = config.get('item_name', 'Unknown Item')
        item_type = config.get('item_type')
        print(f"[*] Processing Item: {item_name} (Type: {item_type})")

        # validation
        source_type = config.get('source_type')
        if source_type == "url":
            if not config.get('source_url'):
                 print(f"[ERROR] 'source_url' is required for source_type='url' (Ref: {item_name}). Skipping.")
                 continue

            if config.get('source_auth_type') == "bearer-token" and not config.get('source_auth_token'):
                print(f"[ERROR] 'source_auth_token' is required for bearer-token auth (Ref: {item_name}). Skipping.")
                continue

            # retrieve data from API endpoint defined in tranformation (config)
            api_response = call_rest_api(config)

            #print(f"[DEBUG] api_response: {api_response}")
            
            if api_response is None:
                print(f"[!] Skipping item {item_name} due to failed API response.")
                continue

            # retrieve the root data element
            data_root_element = config.get('data_root')
            if not data_root_element:
                 print(f"[ERROR] 'data_root' element is missing for item {item_name}. Skipping.")
                 continue
                 
            jsonpath_expression = jpng_parse(f'$..{data_root_element}')
            path_matches = jsonpath_expression.find(api_response)
            
            if not path_matches:
                print(f"[ERROR] Could not find data root element: {data_root_element} for item {item_name}. Skipping.")
                continue

            first_match = path_matches[0]
            data_object = first_match.value

            #print(f"data_object: {data_object}")
            
            # todo: update execution to resume here after retrieving data from source
            try:
                # Normalizing the JSON data into a flat DataFrame
                df = pd.json_normalize(data_object)
            except Exception as e:
                print(f"[ERROR] Failed to normalize data for item {item_name}: {e}. Skipping.")
                continue

            # transform and append using dispatch dictionary
            transformer = TRANSFORMERS.get(item_type)
            if transformer:
                # for nodes we'll pass the base_kind value, but we don't need it for edges
                if item_type == 'node':
                    transformed_data = transformer(df, config, base_kind)
                else:
                    transformed_data = transformer(df, config)

                # append 'transformed_data' to the appropriate graph element (nodes or edges)
                target_list = 'nodes' if item_type == 'node' else 'edges'
                graph_structure['graph'][target_list].extend(transformed_data)
                print(f"[*] Successfully processed {len(transformed_data)} {item_type}s.")
            else:
                print(f"[ERROR] Unknown item_type '{item_type}' defined for item {item_name}. Skipping.")

        # todo: add logic for 'json_file' and 'csv_file' here
        elif source_type != "url":
            print(f"[!] Source type '{source_type}' is not yet implemented. Skipping item {item_name}.")
            
    # todo: add output controls
    #print("[*] Processing complete. Dumping graph to stdout:")
    #json.dump(graph_structure, sys.stdout, indent=4)

    output_file = args.output_file
    if output_file:
        print(f"[*] Writing graph to output file: {output_file}")
        try:       
            with open(output_file, 'w') as f:
                json.dump(graph_structure, f, indent=4)            
            print(f"[>] Wrote graph to {output_file}")
        except:
            print("[ERROR] Failed to write output file")

    print("[*] Done.")

if __name__ == '__main__':
    main()
