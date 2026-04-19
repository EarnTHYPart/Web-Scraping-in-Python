# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
from itemadapter import ItemAdapter
from scrapy.exceptions import DropItem


class VulnerabilitiesPipeline:
    def __init__(self):
        self.seen_cves = set()

    def process_item(self, item, spider):
        adapter = ItemAdapter(item)
        cve_id = (adapter.get("cve_id") or "").strip()
        if not cve_id:
            raise DropItem("Missing cve_id")

        if cve_id in self.seen_cves:
            raise DropItem(f"Duplicate cve_id: {cve_id}")

        summary = adapter.get("summary")
        if summary:
            adapter["summary"] = " ".join(str(summary).split())

        references = adapter.get("references") or []
        adapter["references"] = list(dict.fromkeys(str(ref).strip() for ref in references if ref))

        severity = adapter.get("severity")
        if severity:
            adapter["severity"] = str(severity).strip().upper()

        cvss_score = adapter.get("cvss_score")
        if cvss_score is not None:
            try:
                adapter["cvss_score"] = float(cvss_score)
            except (TypeError, ValueError):
                adapter["cvss_score"] = None

        source_identifier = adapter.get("source_identifier")
        if source_identifier:
            adapter["source_identifier"] = str(source_identifier).strip()

        self.seen_cves.add(cve_id)
        return item
