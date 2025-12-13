from typing import Union, Dict, List, Any
import logging
import yaml
import json
import uuid
import os

# Ensure basic logging is configured (if not already done)
logging.basicConfig(level=logging.INFO, format='%(message)s')

def collect_yaml_data(config: Dict[str, Any]) -> Union[Dict, List, None]:
    """
    Reads data from a local YAML file specified in the configuration.
    Returns the parsed Python object (dict or list) if successful, otherwise None.
    Uses correlation_id for tracing and structured logging.
    
    :param config: A dictionary containing 
    :return: The parsed YAML data (dict or list), or None on error.
    """
    # Generate correlation ID
    correlation_id = str(uuid.uuid4())

    yaml_file_path = config.get('input_file')

    # 1. Validation and Configuration Check
    if not yaml_file_path:
        logging.error(json.dumps({
            "event": "CONFIG_ERROR",
            "correlation_id": correlation_id,
            "message": "Missing 'source_path' in config for YAML collector."
        }))
        return None
    
    if not os.path.exists(yaml_file_path):
        logging.error(json.dumps({
            "event": "FILE_NOT_FOUND_ERROR",
            "correlation_id": correlation_id,
            "path": yaml_file_path,
            "message": "YAML file not found at the specified path."
        }))
        return None

    # 2. Data Collection (File Reading and Parsing)
    try:
        logging.info(json.dumps({
            "event": "YAML_READ_START",
            "correlation_id": correlation_id,
            "path": yaml_file_path,
            "message": "Attempting to read and parse YAML file."
        }))

        with open(yaml_file_path, 'r', encoding='utf-8') as f:
            # Load the YAML content
            data_object = yaml.safe_load(f)
        
        # Structured info log for successful collection
        logging.info(json.dumps({
            "event": "YAML_READ_SUCCESS",
            "correlation_id": correlation_id,
            "path": yaml_file_path,
            "data_type": type(data_object).__name__,
            "message": "Successfully loaded and parsed YAML data."
        }))
        
        return data_object

    except yaml.YAMLError as e:
        # Catch errors specific to YAML parsing (like malformed indentation)
        logging.error(json.dumps({
            "event": "YAML_PARSE_ERROR",
            "correlation_id": correlation_id,
            "path": yaml_file_path,
            "error": str(e),
            "message": "Error parsing YAML file content (malformed syntax or indentation)."
        }))
        return None
        
    except Exception as e:
        logging.error(json.dumps({
            "event": "UNEXPECTED_COLLECTION_ERROR",
            "correlation_id": correlation_id,
            "path": yaml_file_path,
            "error": str(e),
            "message": "An unexpected error occurred during YAML data collection."
        }))
        return None