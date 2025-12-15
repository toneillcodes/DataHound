from requests.adapters import HTTPAdapter
import requests
import logging
import json
import uuid

def collect_http_data(config, session=None):
    """
    Calls an HTTP endpoint using the provided configuration and session.
    Returns raw JSON if successful, otherwise None.
    Adds correlation_id for distributed tracing.
    """
    # generate correlation ID
    correlation_id = str(uuid.uuid4())

    request_url = config.get('source_url')
    request_auth_token = config.get('source_auth_token')
    source_auth_type = config.get('source_auth_type')

    # this shouldn't happen, but let's make sure we have what we need
    if not request_url:
        logging.error(json.dumps({
            "event": "CONFIG_ERROR",
            "correlation_id": correlation_id,
            "message": "Missing 'source_url' in config."
        }))
        return None

    req_headers = {
        "Accept": "application/json"
    }
    if source_auth_type == "bearer-token" and request_auth_token:
        req_headers["Authorization"] = f"Bearer {request_auth_token}"

    try:
        response = session.get(request_url, headers=req_headers, timeout=30)
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