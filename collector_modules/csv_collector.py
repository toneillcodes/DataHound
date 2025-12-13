from typing import Optional
import pandas as pd
import logging
import json
import uuid

def collect_csv_data(config: dict) -> Optional[pd.DataFrame]:
    """
    Loads a CSV file from a path specified in the configuration using pandas.
    Returns a pandas DataFrame if successful, otherwise None.
    Adds correlation_id for tracing.
    """
    # generate correlation ID
    correlation_id = str(uuid.uuid4())

    # retrieve the input_file configuration parameter
    csv_file_path = config.get('input_file')
    
    # optional parameters for pandas.read_csv to consider adding to the config JSON
    sep = config.get('separator', ',')  # Default to comma
    encoding = config.get('encoding', 'utf-8') # Default to utf-8

    # input validation
    if not csv_file_path:
        logging.error(json.dumps({
            "event": "CONFIG_ERROR",
            "correlation_id": correlation_id,
            "message": "Missing 'csv_file_path' in config."
        }))
        return None

    try:
        # load CSV file into a pandas dataframe
        df = pd.read_csv(
            csv_file_path,
            sep=sep,
            encoding=encoding,
            dtype=str
            # Add other common kwargs if needed, e.g., index_col, dtype, parse_dates
        )
        
        # structured info log for successful data load
        logging.info(json.dumps({
            "event": "CSV_LOAD_SUCCESS",
            "correlation_id": correlation_id,
            "file_path": csv_file_path,
            "rows": len(df),
            "columns": len(df.columns),
            "message": "CSV file loaded successfully into DataFrame."
        }))
        
        return df

    except FileNotFoundError:
        logging.error(json.dumps({
            "event": "CSV_FILE_NOT_FOUND",
            "correlation_id": correlation_id,
            "file_path": csv_file_path,
            "message": f"File not found at path: {csv_file_path}"
        }))
        return None
    
    except pd.errors.EmptyDataError:
        logging.error(json.dumps({
            "event": "CSV_EMPTY_DATA",
            "correlation_id": correlation_id,
            "file_path": csv_file_path,
            "message": "No data to parse. File is empty or malformed."
        }))
        return None
        
    except Exception as e:
        # Catch other potential errors like parser errors, encoding errors, etc.
        logging.error(json.dumps({
            "event": "CSV_LOAD_ERROR",
            "correlation_id": correlation_id,
            "file_path": csv_file_path,
            "error_type": type(e).__name__,
            "error_message": str(e)
        }))
        return None