import requests

# global requests Session object
API_SESSION = requests.Session() 

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
        logging.error(f"[API ERROR] Failed to fetch {request_url}: {e}")
        return None
    except json.JSONDecodeError:
        logging.error(f"[API ERROR] Failed to decode JSON response from {request_url}.")
        # response should be defined here, as raise_for_status() and .json() failed
        # check if response is available before accessing .text
        if 'response' in locals() and hasattr(response, 'text'):
             logging.error(f"Response text: {response.text[:200]}...")
        else:
             logging.error("Response object was not available for text logging.")
        return None