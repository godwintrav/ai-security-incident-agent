import os
from typing import Any
import requests
from app.tools.models.search_cve_model import CVEInfo, CVESearchResult

class SearchCVE():
    """This class is responsible for searching for known vulnerabilities for certain products and versions"""

    def __init__(self):
        self.NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.NVD_API_KEY = os.getenv("NVD_API_KEY")

    def _get_description(self, cve: dict[str, Any]) -> str:
        """
        Extract the English CVE description.
        """

        descriptions = cve.get("descriptions", [])

        for description in descriptions:
            if description.get("lang") == "en":
                return description.get("value", "")

        return ""


    def _get_cvss_metrics(self, cve: dict[str, Any]) -> tuple[str | None, float | None]:
        """
        Extract severity and score.

        Prefer CVSS v4.0 when available.
        Fall back to CVSS v3.1.
        Then fall back to CVSS v3.0.
        """

        metrics = cve.get("metrics", {})

        # CVSS v4
        cvss_v4 = metrics.get("cvssMetricV40", [])

        if cvss_v4:
            metric = cvss_v4[0]
            cvss_data = metric.get("cvssData", {})

            return (
                cvss_data.get("baseSeverity"),
                cvss_data.get("baseScore"),
            )

        # CVSS v3.1
        cvss_v31 = metrics.get("cvssMetricV31", [])

        if cvss_v31:
            metric = cvss_v31[0]
            cvss_data = metric.get("cvssData", {})

            return (
                cvss_data.get("baseSeverity"),
                cvss_data.get("baseScore"),
            )

        # CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [])

        if cvss_v30:
            metric = cvss_v30[0]
            cvss_data = metric.get("cvssData", {})

            return (
                cvss_data.get("baseSeverity"),
                cvss_data.get("baseScore"),
            )

        return None, None


    def _get_cwe_ids(self, cve: dict[str, Any]) -> list[str]:
        """
        Extract CWE IDs from the CVE weaknesses section.
        """

        cwe_ids = []

        weaknesses = cve.get("weaknesses", [])

        for weakness in weaknesses:
            descriptions = weakness.get("description", [])

            for description in descriptions:
                value = description.get("value")

                if value and value.startswith("CWE-"):
                    cwe_ids.append(value)

        return list(dict.fromkeys(cwe_ids))


    def _get_references(self, cve: dict[str, Any]) -> list[str]:
        """
        Extract reference URLs.
        """

        references = cve.get("references", [])

        return [
            reference["url"]
            for reference in references
            if reference.get("url")
        ]


    def _parse_cve(self, cve: dict[str, Any]) -> CVEInfo:
        """
        Convert one NVD CVE object into our application's CVEInfo model.
        """

        severity, cvss_score = self._get_cvss_metrics(cve)

        return CVEInfo(
            cve_id=cve["id"],
            description=self._get_description(cve),
            published=cve.get("published"),
            last_modified=cve.get("lastModified"),
            severity=severity,
            cvss_score=cvss_score,
            cwe_ids=self._get_cwe_ids(cve),
            references=self._get_references(cve),
        )


    def search_cve(
        self,
        product: str,
        version: str | None = None,
    ) -> CVESearchResult:
        """
        Search the NVD for vulnerabilities related to a product/version.
        """

        keyword = product

        if version:
            keyword = f"{product} {version}"

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 10,
        }

        headers = {}

        if self.NVD_API_KEY:
            headers["apiKey"] = self.NVD_API_KEY

        try:
            response = requests.get(
                self.NVD_API_URL,
                params=params,
                headers=headers,
                timeout=10,
            )

            response.raise_for_status()

        except requests.exceptions.Timeout as error:
            raise RuntimeError(
                "NVD API request timed out."
            ) from error

        except requests.exceptions.HTTPError as error:
            status_code = error.response.status_code

            if status_code == 403:
                raise RuntimeError(
                    "NVD API rejected the request. "
                    "Check your API key or rate limits."
                ) from error

            if status_code == 429:
                raise RuntimeError(
                    "NVD API rate limit exceeded."
                ) from error

            raise RuntimeError(
                f"NVD API returned HTTP {status_code}."
            ) from error

        except requests.exceptions.RequestException as error:
            raise RuntimeError(
                f"Failed to connect to NVD API: {error}"
            ) from error

        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])

        parsed_vulnerabilities = []

        for vulnerability in vulnerabilities:
            cve = vulnerability.get("cve")

            if not cve:
                continue

            parsed_vulnerabilities.append(
                self._parse_cve(cve)
            )

        return CVESearchResult(
            product=product,
            version=version,
            total_results=data.get("totalResults", 0),
            vulnerabilities=parsed_vulnerabilities,
        )

