from typing import Optional
import pandas as pd
import logging
import json
import uuid
import os

def collect_xml_data(config: dict) -> Optional[pd.DataFrame]:
    """
    Loads an XML file from a path specified in the configuration using pandas.
    Returns a pandas DataFrame if successful, otherwise None.
    Adds correlation_id for tracing.
    
    Configuration Notes:
    - 'input_file' (required): Path to the XML file.
    - 'data_root' (optional): XPath to the nodes to be treated as rows.
      Example: If the XML is <root><item>...</item><item>...</item></root>,
      you would set this to './item' (default is './*').
    - 'encoding' (optional): Encoding of the file (default: 'utf-8').
    """
    # generate correlation ID
    correlation_id = str(uuid.uuid4())

    # retrieve the input_file configuration parameter
    xml_file_path = config.get('input_file')
    
    # optional parameters for pandas.read_xml
    xpath = config.get('data_root', './*') # Default to all direct children of the root
    encoding = config.get('encoding', 'utf-8') # Default to utf-8

    # input validation: check for missing input_file
    if not xml_file_path:
        logging.error(json.dumps({
            "event": "CONFIG_ERROR",
            "correlation_id": correlation_id,
            "message": "Missing 'input_file' in config."
        }))
        return None
    
    # Pre-check for FileNotFoundError and empty file to simplify the main try-block
    if not os.path.exists(xml_file_path):
        logging.error(json.dumps({
            "event": "XML_FILE_NOT_FOUND",
            "correlation_id": correlation_id,
            "file_path": xml_file_path,
            "message": f"File not found at path: {xml_file_path}"
        }))
        return None
    
    # Check for genuinely empty file (a common cause of quick failure)
    if os.path.getsize(xml_file_path) == 0:
        logging.error(json.dumps({
            "event": "XML_EMPTY_DATA",
            "correlation_id": correlation_id,
            "file_path": xml_file_path,
            "message": "No data to parse. File is empty."
        }))
        return None

    try:
        # load XML file into a pandas dataframe
        # read_xml requires the 'lxml' or 'xml.etree.ElementTree' library (default is 'lxml')
        df = pd.read_xml(
            xml_file_path,
            xpath=xpath,
            encoding=encoding
            # 'parser' and 'names' are other useful kwargs to consider adding
        )
        
        # Check if the DataFrame is empty after parsing (e.g., xpath didn't match anything)
        if df.empty:
             logging.error(json.dumps({
                "event": "XML_EMPTY_DATA",
                "correlation_id": correlation_id,
                "file_path": xml_file_path,
                "xpath": xpath,
                "message": "DataFrame is empty after parsing. Check the 'xpath_data_path' configuration."
            }))
             return None

        # structured info log for successful data load
        logging.info(json.dumps({
            "event": "XML_LOAD_SUCCESS",
            "correlation_id": correlation_id,
            "file_path": xml_file_path,
            "rows": len(df),
            "columns": len(df.columns),
            "xpath_used": xpath,
            "message": "XML file loaded successfully into DataFrame."
        }))
        
        return df

    # We catch the general Exception for XML parsing errors, encoding errors, etc., 
    # as pandas.read_xml is less specific with its custom exceptions than read_csv.
    except Exception as e:
        # Catch other potential errors like XML parser errors (e.g., malformed XML)
        # or pandas internal errors.
        logging.error(json.dumps({
            "event": "XML_LOAD_ERROR",
            "correlation_id": correlation_id,
            "file_path": xml_file_path,
            "error_type": type(e).__name__,
            "error_message": str(e)
        }))
        return None