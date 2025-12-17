from requests.adapters import HTTPAdapter
import requests
import logging
import json
import uuid

def collect_http_data(config, session=None, url_params=None):
    """
    Calls an HTTP endpoint using the provided configuration and session.
    Returns raw JSON if successful, otherwise None.
    Adds correlation_id for distributed tracing.
    """
    # generate correlation ID
    correlation_id = str(uuid.uuid4())

    source_url = config.get('source_url')
    source_auth_type = config.get('source_auth_type')

    # this shouldn't happen, but let's make sure we have what we need
    if not source_url:
        logging.error(json.dumps({
            "event": "CONFIG_ERROR",
            "correlation_id": correlation_id,
            "message": "Missing 'source_url' in config."
        }))
        return None

    # url substitution logic for passing a templatized URL in the config with variables in the method params (url_params)
    if source_url and url_params:
        try:
            # .format(**url_params) maps keys in the dict to {placeholders}
            request_url = source_url.format(**url_params)
        except KeyError as e:
            logging.error(json.dumps({
                "event": "URL_FORMAT_ERROR",
                "correlation_id": correlation_id,
                "message": f"Missing required placeholder key: {str(e)}"
            }))
            return None
    else:
        request_url = source_url

    req_headers = {
        "Accept": "application/json"
    }
    req_cookies = {}

    if source_auth_type == "bearer-token":
        request_auth_token = config.get('source_auth_token')
        req_headers["Authorization"] = f"Bearer {request_auth_token}"
    
    elif source_auth_type == "cookie":        
        cookie_name = config.get('source_cookie_name')      
        request_auth_token = config.get('source_auth_token')
        if not cookie_name or not request_auth_token:
            logging.error(json.dumps({
                "event": "INVALID_CONFIG",
                "correlation_id": correlation_id,
                "message": f"The 'source_cookie_name' and 'source_auth_token' properties are required when source_auth_type == cookie"
            }))
            return None            
        else:
            req_cookies[cookie_name] = request_auth_token

    try:
        response = session.get(request_url, headers=req_headers, cookies=req_cookies, timeout=30)
        elapsed_time = response.elapsed.total_seconds()

        # Structured info logging the sent request
        logging.info(json.dumps({
            "event": "HTTP_REQUEST_SENT",
            "correlation_id": correlation_id,
            "url": request_url,
            "status_code": response.status_code,
            "elapsed_seconds": elapsed_time,
            "content_length": len(response.content)
        }))

        response.raise_for_status()

        try:            
            # Structured info logging the sent request
            logging.info(json.dumps({
                "event": "HTTP_REQUEST_SUCCESS",
                "correlation_id": correlation_id,
                "url": request_url,
                "status_code": response.status_code,
                "elapsed_seconds": elapsed_time,
                "content_length": len(response.content)
            }))
            # todo: adjust to handle multiple data formats
            return response.json()
        except json.JSONDecodeError:
            logging.error(json.dumps({
                "event": "HTTP_JSON_DECODE_ERROR",
                "correlation_id": correlation_id,
                "url": request_url,
                "status_code": response.status_code,
                "elapsed_seconds": elapsed_time,
                "response_snippet": response.content[:200].decode(errors="ignore")
            }))
            return None

    except requests.exceptions.RequestException as e:
        logging.error(json.dumps({
            "event": "HTTP_REQUEST_ERROR",
            "correlation_id": correlation_id,
            "url": request_url,
            "error": str(e)
        }))
        return None