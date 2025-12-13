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

def collect_json_data(config: Dict[str, Any]) -> Optional[pd.DataFrame]:
    """
    Reads data from a local JSON file, extracts the data structure using
    the 'data_root' key via JSONPath, and converts it into a pandas DataFrame.
    
    :param config: A dictionary containing parameters
    :return: A pandas DataFrame, or None on error.
    """
    correlation_id = str(uuid.uuid4())
    json_file_path = config.get('input_file')
    data_root_key = config.get('data_root')

    # validation and configuration check
    if not json_file_path or not data_root_key:
        error_msg = f"Missing {'input_file' if not json_file_path else ''}{' and ' if not json_file_path and not data_root_key else ''}{'data_root' if not data_root_key else ''}."
        logging.error(json.dumps({
            "event": "CONFIG_ERROR",
            "correlation_id": correlation_id,
            "message": f"Configuration error for JSON DataFrame loader: {error_msg.strip()}"
        }))
        return None

    if not os.path.exists(json_file_path):
        logging.error(json.dumps({
            "event": "FILE_NOT_FOUND_ERROR",
            "correlation_id": correlation_id,
            "path": json_file_path,
            "message": "JSON file not found at the specified path."
        }))
        return None

    raw_data = None
    try:
        # load the entire file into a dictionary first
        with open(json_file_path, 'r') as f:
            raw_data = json.load(f)
            
        logging.info(json.dumps({
            "event": "JSON_READ_SUCCESS",
            "correlation_id": correlation_id,
            "path": json_file_path,
            "message": "Successfully read JSON file into memory for JSONPath extraction."
        }))

    except json.JSONDecodeError as e:
        logging.error(json.dumps({
            "event": "JSON_DECODE_ERROR",
            "correlation_id": correlation_id,
            "path": json_file_path,
            "error": str(e),
            "message": "Error decoding JSON content (file is malformed)."
        }))
        return None
    except Exception as e:
        logging.error(json.dumps({
            "event": "UNEXPECTED_READ_ERROR",
            "correlation_id": correlation_id,
            "path": json_file_path,
            "error": str(e),
            "message": "An unexpected error occurred during JSON file reading."
        }))
        return None
        
    try:
        # create a jsonpath expression to find all matches for the data root element recursively
        jsonpath_expression = jsonpath_parse(f'$..{data_root_key}')
        
        # check the raw data for jsonpath_expression matches
        path_matches = jsonpath_expression.find(raw_data)
        
        # no matches
        if not path_matches:
            logging.error(json.dumps({
                "event": "DATA_ROOT_ERROR",
                "correlation_id": correlation_id,
                "data_root": data_root_key,
                "message": f"Could not find data root element: {data_root_key} in the JSON structure."
            }))
            return None

        # take the first match
        # todo: tighten this up?
        first_match = path_matches[0]
        data_object = first_match.value

    except Exception as e:
        logging.error(json.dumps({
            "event": "JSONPATH_ERROR",
            "correlation_id": correlation_id,
            "data_root": data_root_key,
            "error": str(e),
            "message": "An error occurred during JSONPath processing."
        }))
        return None

    # convert to pandas dataframe
    try:
        # sanitize the data
        clean_data_object = replace_none_with_string_null(data_object)
        
        # Flatten JSON using json_normalize
        if isinstance(clean_data_object, dict):
             # json_normalize expects a list of records; if it's a single object, wrap it
            df = pd.json_normalize([clean_data_object])
        elif isinstance(clean_data_object, list):
            df = pd.json_normalize(clean_data_object)
        else:
            logging.error(json.dumps({
                "event": "DATA_TYPE_ERROR",
                "correlation_id": correlation_id,
                "data_root": data_root_key,
                "type": str(type(data_object)),
                "message": f"Data under '{data_root_key}' is not a list or dictionary, cannot convert to DataFrame."
            }))
            return None
        
        # structured info log for successful collection
        logging.info(json.dumps({
            "event": "JSON_LOAD_SUCCESS",
            "correlation_id": correlation_id,
            "path": json_file_path,
            "data_root": data_root_key,
            "rows": len(df),
            "columns": len(df.columns),
            "message": "Successfully loaded JSON data from specified root into DataFrame."
        }))

        return df

    except Exception as e:
        logging.error(json.dumps({
            "event": "DATAFRAME_CONVERSION_ERROR",
            "correlation_id": correlation_id,
            "data_root": data_root_key,
            "error": str(e),
            "message": "Error converting extracted JSON data to DataFrame."
        }))
        return None