from typing import Any, Dict, List, Optional
import pandas as pd
import logging

# for connection operations
from jsonpath_ng import parse as jsonpath_parse
from json.decoder import JSONDecodeError
import json

from . import collection

# configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def generate_static_edge(config):
    """
    Prepares a DataFrame to be processed by transform_edge by collecting static values from the config dictionary.

    Parameters:
    - config: The edge configuration dictionary that contains the static data to map.
    """    
    edge_name = config.get('edge_name', 'NA')
    start_id = config.get('start_id', 'NA')
    end_id = config.get('end_id', 'NA')
    source_column = config.get('source_column', 'NA')
    target_column = config.get('target_column', 'NA')
    # setup a dictionary with the details that the tranformation method expects
    # if nothing is getting changed, this could all just be passed by the config dict and this whole call can be avoided. 
    # but there may be some use for this level of control - leaving as the config values may be streamlined soon
    base_data = [{
        "start_id": start_id,
        "end_id": end_id,
        "edge_type": "static",
        "edge_name": edge_name,
        "source_column": source_column,
        "target_column": target_column
    }]
    # create dataframe
    df = pd.DataFrame(base_data)
    # return dataframe for transformation processing
    return df

def prepare_static_start_edge_data(df: pd.DataFrame, config: dict):
    """
    Prepares a DataFrame for transform_edge by injecting static ID values.

    Parameters:
    - df: The DataFrame returned by a collector (contains the dynamic start node data).
    - config: The edge configuration dictionary.
    """
        
    edge_name = config.get('edge_name', 'DEFAULT_EDGE')
    static_start_id = config.get('start_id') # The static ID value
    target_column = config.get('target_column') # Column holding dynamic end ID
    
    # validation checks
    if target_column not in df.columns or static_start_id is None:
        logging.error(f"Missing required data or config for edge '{edge_name}'.")
        return False
    
    # the 'transform_edge' function expects the data to be in the 'source_column' and 'target_column' before the start/end ID calculation.
    # Assign the static ID to the column defined as the 'source_column' in the config.
    df[config['source_column']] = str(static_start_id).strip()

    # The 'target_column' already holds the dynamic ID, so no change is needed there.
    # inject the static edge name into the config for transform_edge
    config['edge_name'] = edge_name
    config['edge_type'] = 'static'
    
    # return the prepared dataframe
    return df

def prepare_static_end_edge_data(df: pd.DataFrame, config: dict):
    """
    Prepares a DataFrame for transform_edge by injecting static ID values.

    Parameters:
    - df: The DataFrame returned by a collector (contains the dynamic start node data).
    - config: The edge configuration dictionary.
    """
        
    edge_name = config.get('edge_name', 'DEFAULT_EDGE')
    source_column = config.get('source_column') # Column holding dynamic start ID
    static_end_id = config.get('end_id') # The static ID value

    # validation checks
    if source_column not in df.columns or static_end_id is None:
        logging.error(f"Missing required data or config for edge '{edge_name}'.")
        return pd.DataFrame() # Return empty dataframe on failure
    
    # the 'transform_edge' function expects the data to be in the 'source_column' and 'target_column' before the start/end ID calculation.
    # Assign the static ID to the column defined as the 'target_column' in the config.
    df[config['target_column']] = str(static_end_id).strip()

    # The 'source_column' already holds the dynamic ID, so no change is needed there.
    # inject the static edge name into the config for transform_edge
    config['edge_name'] = edge_name
    config['edge_type'] = 'static'
    
    # return the prepared dataframe
    return df

def generate_hybrid_edge(config):
    """
    Generates a hybrid edge DataFrame by dynamically selecting a data source
    and applying the appropriate transformation.
    """
    edge_name = config.get('edge_name', 'NA')
    source_type = config.get('source_type')
    dynamic_element = config.get('dynamic_element')
    transformed_df = None # Initialize DataFrame to ensure it's defined
    
    # Select the configuration key that holds the source type based on 'dynamic_element'
    # todo: is there any reason for this? why not just pull from the source_type?
    if dynamic_element == "start":
        source_type_key = 'start_source_type'
    elif dynamic_element in (None, "end"): # Assuming default is 'end' if dynamic_element is not 'start'
        source_type_key = 'end_source_type'
        # todo: remove this? i think it was deprecated. start_id only seems used in this branch, but is otherwise unused.
        # start_id = config.get('start_id', 'NA')
    else:
        # Handle unexpected dynamic_element value gracefully
        raise ValueError(f"Invalid dynamic_element value: {dynamic_element}. Must be 'start', 'end', or None.")

    transformed_df = collection.get_data_from_source(config, source_type_override=source_type)

    if transformed_df is None or (isinstance(transformed_df, bool) and transformed_df is False):
        logging.error(f"Collection failed for hybrid edge: {edge_name}")
        return None

    if dynamic_element == "start":
        transformed_df = prepare_static_end_edge_data(transformed_df, config)
    elif dynamic_element in ("end", None): # Assuming 'end'
        transformed_df = prepare_static_start_edge_data(transformed_df, config)
    
    # source_column = config.get('source_column', 'NA')
    # target_column = config.get('target_column', 'NA')

    return transformed_df

def generate_static_node(config: dict) -> Optional[pd.DataFrame]:
    """
    Creates a single-row DataFrame from static configuration.
    Serializes 'static_id', 'static_name', 'static_kind', and all keys
    from the 'properties' dictionary directly into DataFrame columns.

    Parameters:
    - config: The edge configuration dictionary that contains the static data to map.    
    """
    node_id = config.get('static_id', 'NA')
    node_name = config.get('static_name', 'NA')    
    # default to an empty dict if missing to avoid errors during unpacking
    node_properties = config.get('properties', {}) 

    '''
    # base data dictionary
    base_data = {
        "id": node_id,
        "name": node_name,
        "kind": node_kind
    }
    '''

    # base data dictionary
    base_data = {
        "id": node_id,
        "name": node_name
    }
    
    # use the dictionary unpacking operator (**) to merge properties into the base data dictionary.
    data_row = {
        **base_data,
        **node_properties
    }

    # create the dataframe from a list containing the single data dictionary
    data_series = [data_row]
    df = pd.DataFrame(data_series)
    # return dataframe for transformation processing
    return df

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

def transform_edge(input_object: pd.DataFrame, config: dict):
    df = input_object.copy()
    column_mapping = config.get('column_mapping', {})
    source_col = config['source_column']
    target_col = config['target_column']
    
    # Materialize dotted paths
    source_paths = set(column_mapping.keys()) | {source_col, target_col}
    for path in source_paths:
        if ('.' in path) or (path not in df.columns):
            df[path] = df.apply(lambda row: get_nested(row, path), axis=1)

    df.rename(columns=column_mapping, inplace=True)
    
    if config.get('target_is_multi_valued', False):
        df = df.explode(target_col)
    
    # Filter out nulls
    df = df[df[target_col].notnull() & df[source_col].notnull()]

    # Resolve edge data in a single pass
    edge_type = config.get('edge_type')
    edge_col_id = config.get('edge_column_id')
    edge_name = config.get('edge_name', 'RELATED_TO')
    target_column_id = config.get('target_column_id')

    edge_data = []
    for row in df.to_dict('records'):
        target_val = row[target_col]
        source_val = row[source_col]

        # Resolve end_id
        if isinstance(target_val, dict) and target_column_id:
            end_id = target_val.get(target_column_id)
        else:
            end_id = target_val

        # Resolve edge_kind
        if edge_type == 'from_column':
            kind = row[edge_col_id]        
        else:
            kind = edge_name

        edge_data.append({
            "kind": str(kind or edge_name).strip(),
            "start": {"value": str(source_val).strip()},
            "end": {"value": str(end_id).strip()}
        })
    
    return edge_data

def orig_transform_edge(input_object: pd.DataFrame, config: dict):
    """
    Transforms a DataFrame into a list of edge dictionaries.
    Supports dot-paths in column_mapping, target_column, and source_column 
    to resolve nested objects.
    """
    df = input_object.copy()

    column_mapping: Dict[str, str] = config.get('column_mapping', {})
    
    source_col = config['source_column']
    target_col = config['target_column']
    
    source_paths = set(column_mapping.keys())
    source_paths.add(source_col)
    source_paths.add(target_col)

    # Identify all source paths that might be dotted and need materializing.
    # This includes keys in column_mapping, source_column, and target_column.
    for source_path in source_paths:
        needs_materialization = ('.' in source_path) or (source_path not in df.columns)
        if needs_materialization:
            # Materialize source_path into a temporary column
            df[source_path] = df.apply(lambda row: get_nested(row, source_path), axis=1)

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

    ## todo: add logic to handle situations where no ouput_columns are provided - pass an don't modify the df

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
        #print("Processing edge from_column type")
        edge_object = df[target_col]
        edge_col_id = config['edge_column_id']
        #print(f"edge_col_id: {edge_col_id}")
        # If the target is a dict, extract the nested edge kind. Otherwise, use the value directly.
        df['edge_kind'] = edge_object.apply(
            lambda x: x.get(edge_col_id) if isinstance(x, dict) and x.get(edge_col_id) is not None else x
        ).astype(str).str.strip()
        #print(f"df['edge_kind'] = {df['edge_kind']}")
    else:
        df['edge_kind'] = str(config['edge_name']).strip()

    #print(f"df['edge_kind'] = {df['edge_kind']}")

    # construct edge objects from transformed dataframe
    edge_data = [
        {
            "kind": row['edge_kind'],
            "start": {"value": row['start_id']},
            "end": {"value": row['end_id']}
            # todo: add properties?
        }
        for row in df[['edge_kind', 'start_id', 'end_id']].to_dict('records')
    ]
    
    return edge_data

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
        
        #print(f"df1_subset: {df1_subset}")
        #print("df2_subset: {df2_subset}")
    
        # perform outer merge using the match columns as our key
        merged_df = pd.merge(
            df1_subset,
            df2_subset,
            left_on=match_a,
            right_on=match_b,
            how='outer',
            indicator=True            
        )
        #print("merged_df: {merged_df}")

        # Matched nodes only
        success_df = merged_df[merged_df['_merge'] == 'both'].copy()
        #print(f"success_df: {success_df}")

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
    id_location: str = config['id_location']
    
    #print("(transform_node) Copying object")
    df = input_object.copy()

    #print("(transform_node) Checking materialization")
    # We only need to materialize a column for a source key if it's dotted (contains '.')
    # or if the DF doesn't already have that column name.
    for source_path, target_name in column_mapping.items():
        #print(f"(transform_node) Processing item: {source_path}")
        needs_materialization = ('.' in source_path) #or (source_path not in df.columns)
        #print(f"(transform_node) Processing item: {source_path}")
        # todo: consider controlling this with a 'needs_materialization' property in the config file 
        #needs_materialization = config.get('needs_materialization')
        if needs_materialization:
            # Materialize source_path into a temporary column so .rename() can pick it up.
            df[source_path] = df.apply(lambda row: get_nested(row, source_path), axis=1)
            
    #print("(transform_node) Rename on df")            
    df_renamed = df.rename(columns=column_mapping)
    #print(f"df_renamed: {df_renamed}")

    #print("(transform_node) Column filtering")
    # Filter to requested target columns (post-rename names)
    valid_cols = [col for col in target_columns if col in df_renamed.columns]
    # todo: check on the important fields and drop rows that are missing values we need
    nan_string = config.get('nan_string', 'NULL')

    df_transformed = (
        df_renamed[valid_cols]
        .fillna(nan_string)
        .astype(str)
        .copy()
    )

    # resolve id with dot-path support
    if id_location in df_transformed.columns:
        id_series = df_renamed[id_location]
    else:
        # Create a temporary id column if id_location is dotted/nested
        id_series = df.apply(lambda row: get_nested(row, id_location), axis=1)

    records = df_transformed.to_dict('records')
    #print(f"records: {records}")

    # Convert the id_series to a list for zipping
    id_list = id_series.astype(str).tolist() # Convert to list of strings for safety

    item_kind_type: str = config.get('item_kind_type', 'static')
    if item_kind_type == "from_column":
        item_kind_column_id = config['item_kind_column_id']
        if ('.' in item_kind_column_id):
            # Materialize the column in the current df context
            df_transformed[item_kind_column_id] = df.apply(lambda row: get_nested(row, item_kind_column_id), axis=1)
        
        # FIX: Convert the whole column to a list instead of picking .iloc[0]
        kind_list = df_transformed[item_kind_column_id].astype(str).tolist()
    else:
        # If static, create a list of the same static value for every row
        kind_list = [config['item_kind']] * len(records)

    # Combine the IDs and the properties for final structure
    # Use zip() to iterate through IDs and property dictionaries simultaneously
    node_data = [
        {
            "id": node_id,                       # Use the extracted ID from id_list
            "kinds": [item_kind, source_kind],
            "properties": properties_dict
        }
        for node_id, properties_dict, item_kind in zip(id_list, records, kind_list)
    ]

    return node_data