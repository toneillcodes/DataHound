from ldap3.core.exceptions import LDAPException
import logging
import ldap3
import json
import uuid
import re

# Helper function
def parse_uid_from_dn(dn_string):
    """
    Extracts the value of the 'uid' attribute from a full DN string.
    Example: 'uid=user1,ou=People,dc=example' -> 'user1'
    """
    if not dn_string:
        return None
    
    match = re.match(r'uid=([^,]+)', dn_string, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return dn_string  # Return original if parsing fails

def collect_ldap_data(item_config: dict, bind_password: str, correlation_id=None) -> list:
    """
    Connects to LDAP, performs a search based on item_config, and returns raw entries.
    Adds structured logging and correlation ID for traceability.
    """
    correlation_id = correlation_id or str(uuid.uuid4())

    server_address = item_config['server']
    port = item_config['port']
    use_ssl = item_config.get('use_ssl', True)
    bind_dn = item_config['bind_dn']
    base_dn = item_config['ldap_base_dn']
    search_filter = item_config['ldap_search_filter']
    ldap_attributes = item_config['ldap_attributes']

    server = ldap3.Server(server_address, port=port, use_ssl=use_ssl, get_info=ldap3.ALL)

    try:
        conn = ldap3.Connection(server, user=bind_dn, password=bind_password, auto_bind=True)

        if not conn.bound:
            logging.error(json.dumps({
                "event": "LDAP_BIND_ERROR",
                "correlation_id": correlation_id,
                "server": server_address,
                "bind_dn": bind_dn,
                "message": "Failed to bind to LDAP server"
            }, default=str))
            return None

        logging.info(json.dumps({
            "event": "LDAP_SEARCH_START",
            "correlation_id": correlation_id,
            "base_dn": base_dn,
            "search_filter": search_filter,
            "attributes": ldap_attributes
        }, default=str))

        search_status = conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=ldap_attributes
        )

        if search_status:
            logging.info(json.dumps({
                "event": "LDAP_SEARCH_SUCCESS",
                "correlation_id": correlation_id,
                "entries_found": len(conn.entries)
            }, default=str))

            clean_dn = item_config.get('clean_dn_attributes', [])
            results = []

            for entry in conn.entries:
                row = {}

                for attr in ldap_attributes:
                    values_to_process = entry[attr].values if attr in entry else []

                    if not values_to_process:
                        row[attr] = None
                        continue

                    # DN cleanup if required
                    if attr in clean_dn:
                        value_to_store = [
                            parse_uid_from_dn(v)
                            for v in values_to_process
                            if parse_uid_from_dn(v)
                        ]
                    else:
                        value_to_store = values_to_process

                    # Single vs multi-value handling
                    if len(value_to_store) == 1:
                        row[attr] = value_to_store[0]
                    else:
                        row[attr] = value_to_store

                results.append(row)

            return results

        else:
            logging.warning(json.dumps({
                "event": "LDAP_SEARCH_NO_RESULTS",
                "correlation_id": correlation_id,
                "base_dn": base_dn,
                "search_filter": search_filter
            }, default=str))
            return []

    except LDAPException as e:
        logging.error(json.dumps({
            "event": "LDAP_EXCEPTION",
            "correlation_id": correlation_id,
            "error": str(e)
        }, default=str))
        return None
    except Exception as e:
        logging.error(json.dumps({
            "event": "LDAP_UNEXPECTED_ERROR",
            "correlation_id": correlation_id,
            "error": str(e)
        }, default=str))
        return None
    finally:
        if 'conn' in locals() and conn.bound:
            conn.unbind()