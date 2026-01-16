"""
OWASP ZAP client module for DissoFinito.

Provides thin wrapper functions around the ZAP HTTP API using `requests`.
"""

from typing import Any, Dict, List

import logging

import requests
from flask import current_app
from requests import Response
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)


class ZapClientError(RuntimeError):
    """Custom exception for ZAP client errors."""


def _get_zap_base_url(config: Dict[str, Any]) -> str:
    """
    Resolve the ZAP base URL from the provided config mapping.

    Expected key: "ZAP_API_URL".
    """
    base_url = config.get("ZAP_API_URL") or current_app.config.get("ZAP_API_URL")
    if not base_url:
        raise ZapClientError("ZAP_API_URL is not configured")
    return base_url.rstrip("/")  # ensure no trailing slash


def _get_zap_api_key(config: Dict[str, Any]) -> str:
    """
    Resolve the ZAP API key from the provided config mapping.

    Expected key: "ZAP_API_KEY".
    """
    api_key = config.get("ZAP_API_KEY") or current_app.config.get("ZAP_API_KEY")
    if not api_key:
        raise ZapClientError("ZAP_API_KEY is not configured")
    return api_key


def _handle_response(resp: Response) -> Dict[str, Any]:
    """
    Handle a ZAP HTTP response.

    Raises ZapClientError on non-2xx status or JSON parsing issues.
    """
    try:
        resp.raise_for_status()
    except RequestException as exc:
        logger.error("ZAP API HTTP error: %s", exc)
        raise ZapClientError(f"ZAP API HTTP error: {exc}") from exc

    try:
        data = resp.json()
    except ValueError as exc:
        logger.error("ZAP API response is not valid JSON: %s", exc)
        raise ZapClientError("ZAP API response is not valid JSON") from exc

    # ZAP usually returns JSON objects; surface them as-is
    return data


def start_active_scan(target_url: str, config: Dict[str, Any]) -> str:
    """
    Start an active scan against `target_url`.

    Uses the ZAP endpoint:
    /JSON/ascan/action/scan

    Returns the ZAP scan ID (string).

    :param target_url: URL to actively scan.
    :param config: Config mapping containing ZAP_API_URL and ZAP_API_KEY.
    :raises ZapClientError: on HTTP or API-level errors.
    """
    base_url = _get_zap_base_url(config)
    api_key = _get_zap_api_key(config)

    url = f"{base_url}/JSON/ascan/action/scan/"
    params = {
        "apikey": api_key,
        "url": target_url,
        # Other params (scanPolicyName, recurse, etc.) can be added here
    }

    logger.info("Starting ZAP active scan for target %s", target_url)

    try:
        resp = requests.get(url, params=params, timeout=30)
    except RequestException as exc:
        logger.error("Failed to start ZAP active scan: %s", exc)
        raise ZapClientError(f"Failed to start ZAP active scan: {exc}") from exc

    data = _handle_response(resp)

    scan_id = data.get("scan")
    if scan_id is None:
        # Some ZAP variants use "scanId"; support both for robustness
        scan_id = data.get("scanId")

    if not scan_id:
        logger.error("ZAP did not return a scan ID. Response: %s", data)
        raise ZapClientError("ZAP did not return a scan ID")

    logger.info("ZAP active scan started with ID %s", scan_id)
    return str(scan_id)


def get_scan_status(scan_id: str, config: Dict[str, Any]) -> int:
    """
    Get the status of an active scan as a percentage (0–100).

    Uses the ZAP endpoint:
    /JSON/ascan/view/status/

    :param scan_id: Scan ID returned from start_active_scan.
    :param config: Config mapping containing ZAP_API_URL and ZAP_API_KEY.
    :return: Percentage complete as integer 0–100.
    :raises ZapClientError: on HTTP or API-level errors.
    """
    base_url = _get_zap_base_url(config)
    api_key = _get_zap_api_key(config)

    url = f"{base_url}/JSON/ascan/view/status/"
    params = {"apikey": api_key, "scanId": scan_id}

    logger.debug("Querying ZAP scan status for scan_id=%s", scan_id)

    try:
        resp = requests.get(url, params=params, timeout=15)
    except RequestException as exc:
        logger.error("Failed to query ZAP scan status: %s", exc)
        raise ZapClientError(f"Failed to query ZAP scan status: {exc}") from exc

    data = _handle_response(resp)

    status_str = data.get("status")
    if status_str is None:
        # Some implementations may wrap the status differently; be defensive
        logger.error("ZAP status response missing 'status' field. Response: %s", data)
        raise ZapClientError("ZAP status response missing 'status' field")

    try:
        status_int = int(status_str)
    except (ValueError, TypeError) as exc:
        logger.error("ZAP status '%s' is not an integer: %s", status_str, exc)
        raise ZapClientError(f"ZAP status '{status_str}' is not an integer") from exc

    # Clamp to [0, 100]
    status_int = max(0, min(100, status_int))
    logger.debug("ZAP scan_id=%s status=%d%%", scan_id, status_int)
    return status_int


def fetch_alerts(target_url: str, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Fetch ZAP alerts for the given target URL.

    Uses the ZAP endpoint:
    /JSON/alert/view/alerts/

    :param target_url: Target URL whose alerts should be returned.
    :param config: Config mapping containing ZAP_API_URL and ZAP_API_KEY.
    :return: List of alert objects (raw JSON structures).
    :raises ZapClientError: on HTTP or API-level errors.
    """
    base_url = _get_zap_base_url(config)
    api_key = _get_zap_api_key(config)

    url = f"{base_url}/JSON/alert/view/alerts/"
    params = {
        "apikey": api_key,
        "url": target_url,
        # Optional params like 'start', 'count', 'riskId' can be added later
    }

    logger.info("Fetching ZAP alerts for target %s", target_url)

    try:
        resp = requests.get(url, params=params, timeout=30)
    except RequestException as exc:
        logger.error("Failed to fetch ZAP alerts: %s", exc)
        raise ZapClientError(f"Failed to fetch ZAP alerts: {exc}") from exc

    data = _handle_response(resp)

    alerts = data.get("alerts", [])
    if not isinstance(alerts, list):
        logger.error("ZAP alerts response malformed. 'alerts' is not a list: %s", data)
        raise ZapClientError("ZAP alerts response malformed; 'alerts' is not a list")

    logger.info("Retrieved %d alerts from ZAP for target %s", len(alerts), target_url)
    return alerts
