# Web Scraping in Python

This repository contains a Scrapy project for collecting CVE (Common Vulnerabilities and Exposures) records and exporting structured results.

## Project Overview

The spider is designed to:
- Search CVEs by keyword
- Optionally filter by year
- Limit number of records returned
- Export data to JSON/JSONL via Scrapy feed exports

Collected fields include:
- `cve_id`
- `summary`
- `detail_url`
- `references`
- `search_keyword`
- `published`
- `last_modified`
- `source_identifier`
- `severity`
- `cvss_score`
- `cvss_vector`

## Structure

- `scrapy.cfg` - Scrapy configuration entry point
- `vulnerabilities/spiders/cve.py` - Main CVE spider
- `vulnerabilities/items.py` - Item schema
- `vulnerabilities/pipelines.py` - Validation and deduplication logic
- `vulnerabilities/settings.py` - Project settings

## Setup

1. Create and activate a virtual environment.
2. Install dependencies.

```powershell
python -m venv env
env\Scripts\Activate.ps1
pip install scrapy
```

## Run

From the repository root (where `scrapy.cfg` is located):

```powershell
scrapy crawl cve -a keyword=python -a limit=10 -O output.json
```

Optional arguments:
- `keyword` (default: `python`)
- `limit` (default: `25`)
- `year` (optional)

Example:

```powershell
scrapy crawl cve -a keyword=openssl -a year=2024 -a limit=20 -O cves_2024.json
```

## Notes

- Keep crawl rate polite using Scrapy settings.
- Review exported output before downstream analysis.
- Use the pipeline to enforce item quality and remove duplicates.
