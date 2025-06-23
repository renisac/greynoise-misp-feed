
# greynoise-misp-feed

## Overview

greynoise-misp-feed is a Python utility that integrates GreyNoise threat intelligence with MISP (Malware Information Sharing Platform). It queries the GreyNoise API using the official SDK and transforms the results into MISP-compatible JSON feeds, enabling seamless enrichment of IP indicators in your threat intelligence workflows.

## Features

- Queries GreyNoise using custom search filters.
- Converts results into MISP greynoise-ip objects with enriched attributes.
- Generates a valid manifest.json for MISP feed ingestion.
- Supports batching and scroll-based pagination to handle large datasets efficiently.
- Environment variable configuration for flexible deployment.

## Getting Started

### Prerequisites

- Python 3.7+
- GreyNoise API key
- GreyNoise SDK v3.0.0+
- MISP instance (for feed ingestion)

### Installation

pip install greynoise

## Environment Variables

| Variable | Description | Default |
|---------|-------------|---------|
| GREYNOISE_API_KEY | Your GreyNoise API key | Required |
| FEED-DATA-PATH | Output directory for feed data | feed-data/greynoise |
| GREYNOISE_FEED_BATCH_SIZE | Number of results per API call (max 10,000) | 1000 |
| GREYNOISE_FEED_MAX_RESULTS | Max results to fetch per query (0 = unlimited) | 10000 |
| GREYNOISE_FEED_LOG_LEVEL | Logging level (DEBUG, INFO, etc.) | INFO |

## Usage

Run the script:

```python3 greynoise-misp-json.py```

This will:

1. Query GreyNoise using the predefined queries.
2. Generate MISP-compatible JSON files for each query.
3. Create a manifest.json to support MISP feed ingestion.
4. Output all files to feed-data/greynoise/.

You can then configure this folder as a local feed in your MISP instance.

## Default Queries

The following GreyNoise queries are used by default:

```
queries = [
  "classification:malicious last_seen:1d",
  "classification:suspicious last_seen:1d",
  "classification:benign last_seen:1d"
]
```

You can customize these queries in the script to suit your threat intelligence needs.

## Output Structure

Each query generates a JSON file named with a UUID, containing a MISP event with greynoise-ip objects. A manifest.json is also created to allow MISP to ingest the feed.

```
feed-data/
└── greynoise/
    ├── manifest.json
    ├── <uuid1>.json
    ├── <uuid2>.json
    └── ...
```

## MISP Object Definition

This project includes an updated MISP object definition for greynoise-ip, enriched with additional attributes provided by the GreyNoise API.
