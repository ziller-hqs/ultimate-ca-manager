"""Plesk DNS provider using the Plesk XML API."""
import logging
import xml.etree.ElementTree as XmlBuilder
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import defusedxml.ElementTree as SafeXml
import requests

from .base import BaseDnsProvider

logger = logging.getLogger(__name__)


class PleskDnsProvider(BaseDnsProvider):
    PROVIDER_TYPE = "plesk"
    PROVIDER_NAME = "Plesk"
    PROVIDER_DESCRIPTION = "Plesk XML API (self-hosted)"
    REQUIRED_CREDENTIALS = ["server_url", "api_key"]
    OPTIONAL_CREDENTIALS = ["verify_ssl"]

    API_PATH = "/enterprise/control/agent.php"

    def __init__(self, credentials: Dict[str, Any]):
        super().__init__(credentials)
        self.endpoint = self._build_endpoint(self.credentials["server_url"])
        verify_ssl = self.credentials.get("verify_ssl", True)
        self.verify_ssl = verify_ssl if isinstance(verify_ssl, bool) else str(verify_ssl).lower() not in {"0", "false", "no"}
        self._sites_cache: Optional[List[Dict[str, Any]]] = None

    @classmethod
    def _build_endpoint(cls, server_url: str) -> str:
        server_url = server_url.strip().rstrip("/")
        parsed = urlparse(server_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Plesk Server URL must be a valid HTTP or HTTPS URL")
        if parsed.query or parsed.fragment:
            raise ValueError("Plesk Server URL must not contain a query string or fragment")
        if parsed.path.rstrip("/").endswith(cls.API_PATH):
            return server_url
        return f"{server_url}{cls.API_PATH}"

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "text/xml",
            "Accept": "text/xml",
            "KEY": self.credentials["api_key"],
        }

    def _request(self, packet: XmlBuilder.Element) -> Tuple[bool, Any]:
        payload = XmlBuilder.tostring(packet, encoding="utf-8", xml_declaration=True)
        try:
            response = requests.post(
                self.endpoint,
                headers=self._headers(),
                data=payload,
                timeout=30,
                verify=self.verify_ssl,
            )
            if response.status_code >= 400:
                return False, self._error(response)
            try:
                return True, SafeXml.fromstring(response.text)
            except SafeXml.ParseError as exc:
                return False, self._failure(exc, "Invalid XML response: ")
        except requests.RequestException as exc:
            logger.error("Plesk API request failed: %s", self._failure(exc))
            return False, self._failure(exc)

    def _operation_error(self, result: XmlBuilder.Element) -> str:
        code = (result.findtext("errcode") or "unknown").strip()
        text = (result.findtext("errtext") or "Unknown Plesk API error").strip()
        return self.redact_secrets(f"Plesk API error {code}: {text}")

    def _first_error(self, results: List[XmlBuilder.Element]) -> Optional[str]:
        for result in results:
            if (result.findtext("status") or "").strip().lower() == "error":
                return self._operation_error(result)
        return None

    @staticmethod
    def _packet(operator: str, operation: str) -> Tuple[XmlBuilder.Element, XmlBuilder.Element]:
        packet = XmlBuilder.Element("packet")
        operator_node = XmlBuilder.SubElement(packet, operator)
        operation_node = XmlBuilder.SubElement(operator_node, operation)
        return packet, operation_node

    def _get_sites(self) -> Tuple[bool, Any]:
        if self._sites_cache is not None:
            return True, self._sites_cache

        packet, operation = self._packet("site", "get")
        XmlBuilder.SubElement(operation, "filter")
        dataset = XmlBuilder.SubElement(operation, "dataset")
        XmlBuilder.SubElement(dataset, "gen_info")

        success, response = self._request(packet)
        if not success:
            return False, response

        results = response.findall("./site/get/result")
        error = self._first_error(results)
        if error:
            return False, error

        sites: List[Dict[str, Any]] = []
        for result in results:
            site_id = result.findtext("id")
            name = result.findtext("./data/gen_info/ascii-name") or result.findtext("./data/gen_info/name")
            if site_id and name:
                sites.append({"id": int(site_id), "name": self._normalise_name(name)})
        self._sites_cache = sites
        return True, sites

    def _find_site(self, name: str) -> Tuple[bool, Any]:
        success, sites = self._get_sites()
        if not success:
            return False, sites
        site = self.find_zone(name, sites, key=lambda item: item["name"])
        if not site:
            return False, f"Could not find Plesk site for {name}"
        return True, site

    def create_txt_record(
        self,
        domain: str,
        record_name: str,
        record_value: str,
        ttl: int = 300,
    ) -> Tuple[bool, str]:
        del ttl  # Plesk applies the DNS zone's TTL; add_rec has no TTL field.
        record_name = self._normalise_name(record_name)
        success, site = self._find_site(record_name or domain)
        if not success:
            return False, str(site)

        packet, operation = self._packet("dns", "add_rec")
        XmlBuilder.SubElement(operation, "site-id").text = str(site["id"])
        XmlBuilder.SubElement(operation, "type").text = "TXT"
        XmlBuilder.SubElement(operation, "host").text = record_name
        XmlBuilder.SubElement(operation, "value").text = record_value

        success, response = self._request(packet)
        if not success:
            return False, f"Failed to create record: {response}"
        result = response.find("./dns/add_rec/result")
        if result is None:
            return False, "Failed to create record: Plesk returned no result"
        if (result.findtext("status") or "").strip().lower() != "ok":
            return False, f"Failed to create record: {self._operation_error(result)}"

        record_id = result.findtext("id")
        logger.info("Plesk: Created TXT record %s", record_name)
        suffix = f" (ID {record_id})" if record_id else ""
        return True, f"Record created successfully{suffix}"

    def delete_txt_record(self, domain: str, record_name: str) -> Tuple[bool, str]:
        record_name = self._normalise_name(record_name)
        success, site = self._find_site(record_name or domain)
        if not success:
            return False, str(site)

        packet, operation = self._packet("dns", "get_rec")
        record_filter = XmlBuilder.SubElement(operation, "filter")
        XmlBuilder.SubElement(record_filter, "site-id").text = str(site["id"])
        success, response = self._request(packet)
        if not success:
            return False, f"Failed to list records: {response}"

        results = response.findall("./dns/get_rec/result")
        error = self._first_error(results)
        if error:
            return False, f"Failed to list records: {error}"

        record_ids = []
        for result in results:
            record_type = (result.findtext("./data/type") or "").strip().upper()
            host = self._normalise_name(result.findtext("./data/host"))
            record_id = result.findtext("id")
            if record_type == "TXT" and host == record_name and record_id:
                record_ids.append(record_id)

        if not record_ids:
            return True, "Record not found (already deleted?)"

        delete_packet = XmlBuilder.Element("packet")
        dns = XmlBuilder.SubElement(delete_packet, "dns")
        for record_id in record_ids:
            delete_operation = XmlBuilder.SubElement(dns, "del_rec")
            delete_filter = XmlBuilder.SubElement(delete_operation, "filter")
            XmlBuilder.SubElement(delete_filter, "id").text = record_id

        success, response = self._request(delete_packet)
        if not success:
            return False, f"Failed to delete record: {response}"

        errors = []
        for result in response.findall("./dns/del_rec/result"):
            status = (result.findtext("status") or "").strip().lower()
            code = (result.findtext("errcode") or "").strip()
            if status == "error" and code != "1013":
                errors.append(self._operation_error(result))
        if errors:
            return False, f"Failed to delete record: {'; '.join(errors)}"

        logger.info("Plesk: Deleted %d TXT record(s) for %s", len(record_ids), record_name)
        return True, f"Deleted {len(record_ids)} record(s) successfully"

    def test_connection(self) -> Tuple[bool, str]:
        success, sites = self._get_sites()
        if not success:
            return False, f"Connection failed: {sites}"
        names = [site["name"] for site in sites]
        sample = f": {', '.join(names[:5])}" if names else ""
        return True, f"Connected. Found {len(sites)} accessible site(s){sample}"

    @classmethod
    def get_credential_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "server_url",
                "label": "Plesk Server URL",
                "type": "text",
                "required": True,
                "help": "Plesk panel URL, for example https://plesk.example.com:8443",
            },
            {
                "name": "api_key",
                "label": "API Key",
                "type": "password",
                "required": True,
                "help": "Plesk secret key with permission to manage the hosted DNS zones",
            },
            {
                "name": "verify_ssl",
                "label": "Verify TLS Certificate",
                "type": "checkbox",
                "required": False,
                "default": True,
                "help": "Disable only when the Plesk server uses an untrusted self-signed certificate",
            },
        ]