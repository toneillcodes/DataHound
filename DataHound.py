from jsonpath_ng import parse as jsonpath_parse

import pandas as pd
import argparse
import logging
import json
import sys
import os

from datahound import core
from datahound import collection

# might be used for correlation, not needed yet
import uuid

# configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

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

def process_config_item(config, source_kind=None):
    """Handles the full lifecycle of a single config item: Validation -> Collection -> Transformation."""
    item_name = config.get('item_name', 'NA')
    item_type = config.get('item_type')

    # 1. Validation
    if not item_type:
        logging.error(f"'item_type' is required. Skipping item: {item_name}.")
        return None, None

    # 2. Routing / Dispatching
    # Direct processors handle their own data collection (like hybrid edges)
    item_type_direct_processors = {
        "static_edge": core.generate_static_edge,
        "hybrid_edge": core.generate_hybrid_edge                
    }

    df = None
    if item_type in item_type_direct_processors:                
        df = item_type_direct_processors[item_type](config)
    
    elif item_type in ("node", "edge"):
        # We delegate the lookup and execution to the shared dispatcher
        df = collection.get_data_from_source(config)
    
    else:
        logging.warning(f"Item type '{item_type}' not implemented. Skipping.")
        return None, None

    # Validate that we actually got a DataFrame back
    if df is None or (isinstance(df, bool) and df is False) or (isinstance(df, pd.DataFrame) and df.empty):
        logging.warning(f"Collection returned no data for: {item_name}")
        return None, None

    # 3. Transformation
    TRANSFORMERS = {
        'node': core.transform_node, 
        'edge': core.transform_edge,
        'static_edge': core.transform_edge, 
        'hybrid_edge': core.transform_edge
    }

    transformer = TRANSFORMERS.get(item_type)
    if not transformer:
        logging.error(f"No transformer for type: '{item_type}'.")
        return None, None

    # Apply transformation logic
    try:
        if item_type == 'node':
            #print(f"Using tranformation function: {transformer}")
            transformed_data = transformer(df, config, source_kind)
        else:
            transformed_data = transformer(df, config)
            
        target_list = 'nodes' if item_type == 'node' else 'edges'
        return target_list, transformed_data

    except Exception as e:
        logging.error(f"Transformation failed for {item_name}: {e}")
        return None, None

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
            # centralized processing logic moved to a dedicated method which parses the config and invokes the dispatcher
            # target_list should be either 'node' or 'edge' to indicate which part of the graph is being returned
            # data contains the processed and transformed graph data to be appended
            target_list, data = process_config_item(config, source_kind)
            
            if target_list and data:
                graph_structure['graph'][target_list].extend(data)
                logging.info(f"Successfully added {len(data)} items to {target_list}.")

        # done processing, output graph              
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
            if core.connect_graphs(graph_a, root_a, id_a, match_a, graph_b, root_b, id_b, match_b, edge_kind, output_file):
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