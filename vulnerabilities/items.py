# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class VulnerabilitiesItem(scrapy.Item):
    cve_id = scrapy.Field()
    summary = scrapy.Field()
    detail_url = scrapy.Field()
    references = scrapy.Field()
    search_keyword = scrapy.Field()
    published = scrapy.Field()
    last_modified = scrapy.Field()
    source_identifier = scrapy.Field()
    severity = scrapy.Field()
    cvss_score = scrapy.Field()
    cvss_vector = scrapy.Field()
