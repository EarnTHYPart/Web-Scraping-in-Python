from urllib.parse import urlencode

import scrapy

from vulnerabilities.items import VulnerabilitiesItem


class CveSpider(scrapy.Spider):
    name = "cve"
    allowed_domains = ["services.nvd.nist.gov", "cveawg.mitre.org"]
    nvd_search_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_detail_api = "https://cveawg.mitre.org/api/cve"

    def __init__(self, keyword="python", year=None, limit=25, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keyword = keyword.strip() or "python"
        self.year = int(year) if year is not None else None
        self.limit = max(1, int(limit))

    def start_requests(self):
        params = {
            "keywordSearch": self.keyword,
            "resultsPerPage": self.limit,
            "startIndex": 0,
        }
        yield scrapy.Request(
            url=f"{self.nvd_search_url}?{urlencode(params)}",
            callback=self.parse_search_results,
        )

    def parse_search_results(self, response):
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            self.logger.warning("No CVE results found from NVD for keyword: %s", self.keyword)
            return

        count = 0
        for entry in vulnerabilities:
            cve = entry.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue

            if self.year is not None and not cve_id.startswith(f"CVE-{self.year}-"):
                continue

            description = self._pick_english_description(cve.get("descriptions") or [])

            count += 1
            yield scrapy.Request(
                url=f"{self.cve_detail_api}/{cve_id}",
                callback=self.parse_detail,
                meta={
                    "cve_id": cve_id,
                    "description": description,
                    "search_keyword": self.keyword,
                },
            )
            if count >= self.limit:
                break

    def parse_detail(self, response):
        payload = response.json() if response.text else {}
        references = self._extract_references(payload)

        item = VulnerabilitiesItem()
        item["cve_id"] = response.meta.get("cve_id")
        item["summary"] = response.meta.get("description")
        item["detail_url"] = response.url
        item["references"] = references
        item["search_keyword"] = response.meta.get("search_keyword")
        yield item

    @staticmethod
    def _pick_english_description(descriptions):
        for desc in descriptions:
            if (desc.get("lang") or "").lower() == "en":
                return (desc.get("value") or "").strip() or None
        return None

    @staticmethod
    def _extract_references(payload):
        refs = []
        containers = ((payload or {}).get("containers") or {})

        cna_refs = ((containers.get("cna") or {}).get("references") or [])
        refs.extend(ref.get("url") for ref in cna_refs if ref.get("url"))

        for adp_entry in containers.get("adp") or []:
            for ref in (adp_entry.get("references") or []):
                if ref.get("url"):
                    refs.append(ref.get("url"))

        return list(dict.fromkeys(refs))
