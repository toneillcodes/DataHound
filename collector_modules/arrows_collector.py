from jsonpath_ng import parse as jsonpath_parse
from typing import Dict, Any, Optional
import pandas as pd
import logging
import json
import uuid
import os

# copied from DataHound.py
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

def collect_arrows_node_data(config: Dict[str, Any]) -> Dict[str, pd.DataFrame]:
    """
    Parses Arrows.app JSON nodes into DataFrames.
    Specifically extracts 'kind' from properties and handles ID mapping.
    """
    correlation_id = str(uuid.uuid4())
    json_file_path = config.get('source_path')

    if not json_file_path or not os.path.exists(json_file_path):
        logging.error(json.dumps({"event": "FILE_ERROR", "message": "File not found"}))
        return None

    try:
        with open(json_file_path, 'r') as f:
            raw_data = json.load(f)
            
        # 1. Process Nodes
        nodes_raw = raw_data.get('nodes', [])
        node_records = []
        for n in nodes_raw:
            # Extract Kind from properties
            props = n.get('properties', {})
            kind = props.get('kind', 'Unknown')
            
            # Build clean record
            node_record = {
                "id": n.get('id'), # Use the top-level ID
                "kind": kind,
                "caption": n.get('caption'),
                "properties": replace_none_with_string_null(props)
            }
            node_records.append(node_record)
        
        df_nodes = pd.DataFrame(node_records)

        logging.info(json.dumps({
            "event": "ARROWS_LOAD_SUCCESS",
            "nodes_count": len(df_nodes)
        }))

        return df_nodes

    except Exception as e:
        logging.error(json.dumps({"event": "PARSING_ERROR", "error": str(e)}))
        return None

def collect_arrows_edge_data(config: Dict[str, Any]) -> Dict[str, pd.DataFrame]:
    """
    Parses Arrows.app JSON relationships into DataFrames.
    Specifically extracts 'kind' from properties and handles ID mapping.
    """
    correlation_id = str(uuid.uuid4())
    json_file_path = config.get('source_path')

    if not json_file_path or not os.path.exists(json_file_path):
        logging.error(json.dumps({"event": "FILE_ERROR", "message": "File not found"}))
        return None

    try:
        with open(json_file_path, 'r') as f:
            raw_data = json.load(f)

        # 2. Process Relationships (Edges)
        edges_raw = raw_data.get('relationships', [])
        edge_records = []
        for e in edges_raw:
            edge_record = {
                "id": e.get('id'),
                "fromId": e.get('fromId'),
                "toId": e.get('toId'),
                "type": e.get('type'),
                "properties": replace_none_with_string_null(e.get('properties', {}))
            }
            edge_records.append(edge_record)
            
        df_edges = pd.DataFrame(edge_records)

        logging.info(json.dumps({
            "event": "ARROWS_LOAD_SUCCESS",
            "edges_count": len(df_edges)
        }))

        return df_edges

    except Exception as e:
        logging.error(json.dumps({"event": "PARSING_ERROR", "error": str(e)}))
        return None    