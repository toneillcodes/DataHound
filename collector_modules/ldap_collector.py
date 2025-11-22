from ldap3.core.exceptions import LDAPException
import logging
import ldap3
import re

# helper function
def parse_uid_from_dn(dn_string):
    """
    Extracts the value of the 'uid' attribute from a full DN string.
    Example: 'uid=user1,ou=People,dc=example' -> 'user1'
    """
    if not dn_string:
        return None
    
    # Regular expression to find 'uid=' followed by any characters until the next comma or end of string
    match = re.match(r'uid=([^,]+)', dn_string, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # Add logic here for other common identifiers like 'cn' if needed
    return dn_string # Return original if parsing fails

def fetch_ldap_data(item_config: dict, bind_password: str) -> list or None: # type: ignore
    """
    Connects to LDAP, performs a search based on item_config, and returns raw entries.
    """
    server_address = item_config['server']
    port = item_config['port']
    use_ssl = item_config.get('use_ssl', False)
    bind_dn = item_config['bind_dn']
    base_dn = item_config['ldap_base_dn']
    search_filter = item_config['ldap_search_filter']
    attributes = item_config['ldap_attributes']

    server = ldap3.Server(server_address, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

    try:
        conn = ldap3.Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

        if not conn.bound:
            logging.error(f"LDAP ERROR: Failed to bind to LDAP server as {bind_dn}")
            return None

        logging.info(f"Searching for data in: {base_dn} with filter: {search_filter}")
        conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes
        )
        
        # does this item have any DN values to be trimmed?
        clean_dn = item_config.get('clean_dn_attributes', [])
        
        results = []
        
        for entry in conn.entries:
            ldap_attributes = entry.entry_attributes 
            
            row = {}
            for attr, values in ldap_attributes.items():
                
                # Check if values is not an empty list
                if values and isinstance(values, list):
                    
                    # Check if this attribute is configured for DN cleanup
                    if attr in clean_dn: 
                        # apply DN cleanup to all values in the list
                        cleaned_values = [parse_uid_from_dn(v) for v in values]
                        # what should we do with failures?
                        values_to_store = [v for v in cleaned_values if v]
                    else:
                        values_to_store = values
                        
                    # single/multi-value handling logic
                    if len(values_to_store) == 1:
                        # single value, grab the value
                        row[attr] = values_to_store[0]
                    else:
                        # multi-valued, store the list for pandas.explode/normalize later
                        row[attr] = values_to_store
                else:
                    # set a value for empty attributes
                    row[attr] = None
            
            results.append(row)

        logging.info(f"Found {len(results)} LDAP entries.")
        return results

    except LDAPException as e:
        logging.error(f"LDAP Error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during LDAP fetch: {e}")
        return None
    finally:
        if 'conn' in locals() and conn.bound:
            conn.unbind()