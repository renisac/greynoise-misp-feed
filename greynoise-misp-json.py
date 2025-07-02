import os, logging, tempfile, shutil, json, uuid, datetime, time, traceback
from typing import Optional
from greynoise.api import GreyNoise, APIConfig

# Set your API key securely
DATA_PATH = os.path.join(os.getenv("FEED-DATA-PATH", "feed-data"), "greynoise")
#How many results to fetch in each batch. Max 10,000. Used to limit memory usage
BATCH_SIZE = int(os.getenv("GREYNOISE_FEED_BATCH_SIZE", 1000))
# Max results to fetch. Set to 0 for no limit
MAX_RESULTS = int(os.getenv("GREYNOISE_FEED_MAX_RESULTS", 0))
# Set log level from environment, default to INFO
LOG_LEVEL = getattr(logging, os.getenv("GREYNOISE_FEED_LOG_LEVEL", "INFO").upper(), logging.INFO)

queries = [
    "classification:malicious last_seen:1d",
    "classification:suspicious last_seen:1d"
]

# Configure logging
logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_greynoise_session() -> Optional[GreyNoise]:
    """Initialize and return a GreyNoise session with error handling."""
    try:
        GN_API_KEY = os.environ.get("GN_API_KEY")
        if not GN_API_KEY:
            logger.error("GN_API_KEY environment variable not set")
            return None
        
        api_config = APIConfig(api_key=GN_API_KEY, integration_name="misp-feed-script-v2.0")
        session = GreyNoise(api_config)
        return session
    except Exception as e:
        logger.error(f"Failed to initialize GreyNoise session: {e}")
        return None

def update_manifest(queries):
    # Define the template
    template = {
        "info": "",
        "Orgc": {
            "id": "1",
            "name": "GREYNOISE",
            "uuid": "ad3d37aa-1b47-4a56-aee8-4ca163520221"
        },
        "analysis": "0",
        "timestamp": "",
        "date": "",
        "threat_level_id": "4",
        "Tag": [
            {
                "colour": "#FFC000",
                "name": "tlp:amber"
            }
        ]
    }

    # Determine manifest path from environment variable
    base_path = os.getenv("MISP-FEED-DATA-PATH", "feed-data")
    manifest_dir = os.path.join(base_path, "greynoise")
    manifest_path = os.path.join(manifest_dir, "manifest.json")

    # Ensure directory exists
    os.makedirs(manifest_dir, exist_ok=True)

    # Normalize queries
    normalized_queries = [q.strip() for q in queries]

    # Load or initialize manifest
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    else:
        manifest = {}

    # Get current timestamp and date
    current_timestamp = str(int(datetime.datetime.now().timestamp()))
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')

    # Track UUIDs to retain and query-to-UUID mapping
    uuids_to_keep = set()
    query_uuid_map = {}

    # Process each query
    for query_info in normalized_queries:
        found = False

        for item_uuid, item_data in manifest.items():
            if item_data['info'] == query_info:
                item_data['timestamp'] = current_timestamp
                item_data['date'] = current_date
                uuids_to_keep.add(item_uuid)
                query_uuid_map[query_info] = item_uuid
                found = True
                break

        if not found:
            new_uuid = str(uuid.uuid4())
            new_item = template.copy()
            new_item['info'] = query_info
            new_item['timestamp'] = current_timestamp
            new_item['date'] = current_date
            manifest[new_uuid] = new_item
            uuids_to_keep.add(new_uuid)
            query_uuid_map[query_info] = new_uuid
    # Remove entries not in current queries
    manifest = {uuid: data for uuid, data in manifest.items() if uuid in uuids_to_keep}

    # Save the updated manifest
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=4)

    return query_uuid_map

# Create the standard MISP JSON structure and split it at the Object key for stream writing api results to file
def create_greynoise_misp_json_start_end(uuid):
    current_date = datetime.date.today().strftime("%Y-%m-%d")
    current_timestamp = str(int(time.time()))

    misp_json = {
                "Event": {
                    "date": current_date,
                    "threat_level_id": "4",
                    "info": "GreyNoise Feed",
                    "published": True,
                    "uuid": uuid,
                    "analysis": "0",
                    "timestamp": current_timestamp,
                    "distribution": "2",
                    "publish_timestamp": "0",
                    "Orgc": {
                        "name": "GREYNOISE",
                        "uuid": "0db8495b-917d-4b34-ad2c-be7eeaa19c7f",
                    },
                    "Tag": [
                        {
                            "name": "tlp:amber",
                            "colour": "#FFC000",
                            "local": False,
                            "relationship_type": None
                        }
                    ],
                    "Attribute": [],
                    "Object": []
                }
            }

    json_str = json.dumps(misp_json, indent=4)
    split_token = '"Object": ['
    if split_token not in json_str:
        logger.error("Split token not found in MISP JSON structure")
        return None, None
    start_str, end_str = json_str.split(split_token, 1)
    start_str += split_token
    return start_str, end_str

def create_attribute(attr_type, object_relation, value, to_ids=False, disable_correlation=True):
    return {
        "type": attr_type,
        "category": "Network activity" if attr_type in ["ip-src", "AS", "hostname", "domain"] else "Other",
        "to_ids": to_ids,
        "distribution": "5",
        "comment": "",
        "deleted": False,
        "disable_correlation": disable_correlation,
        "object_relation": object_relation,
        "value": value
    }

def get_attributes(item):
    logger.debug(json.dumps(item, indent=2))

    is_intel = item.get("internet_scanner_intelligence", {})
    is_intel_meta = is_intel.get("metadata", {})

    if is_intel.get("classification") == "malicious":
        is_malicious = True
    else:
        is_malicious = False
    return [
        create_attribute("text", "classification", is_intel.get("classification")),
        create_attribute("ip-src", "ip-src", item.get("ip"), to_ids=is_malicious, disable_correlation=False),
        create_attribute("text", "actor", is_intel.get("actor")),
        create_attribute("AS", "asn", is_intel_meta.get("asn")),
        create_attribute("text", "source_country", is_intel_meta.get("source_country")),
        create_attribute("hostname", "rdns", is_intel_meta.get("rdns"), disable_correlation=False),
        create_attribute("domain", "rdns_parent", is_intel_meta.get("rdns_parent")),
        create_attribute("boolean", "bot", str(int(is_intel.get("bot")))),
        create_attribute("boolean", "tor", str(int(is_intel.get("tor")))),
        create_attribute("boolean", "vpn", str(int(is_intel.get("vpn"))))
    ]

def create_greynoise_misp_object_json(item):
    return {
        "name": "greynoise-ip",
        "meta-category": "network",
        "description": "GreyNoise IP Information",
        "template_uuid": "6B14A94A-46E4-4B82-B24D-0DBF8E8B3FD9",
        "template_version": "2",
        "timestamp": "1750255912",
        "distribution": "5",
        "comment": "",
        "deleted": False,
        "first_seen": item.get("internet_scanner_intelligence", {}).get("first_seen"),
        "last_seen": item.get("internet_scanner_intelligence", {}).get("last_seen"),
        "Attribute": get_attributes(item),
    }

def main():
    # Update the MISP manifest.json file based on current queries defined above and get the uuids to use for each query's filename
    query_uuid_map = update_manifest(queries)
    # Print the query-to-UUID mapping for debugging
    for query, uuid in query_uuid_map.items():
        logger.debug(f"{query}: {uuid}")

    # Initialize GreyNoise client
    session = get_greynoise_session()
    if not session:
        logger.error("Failed to initialize GreyNoise session")
        return

    for query, uuid in query_uuid_map.items():
        logger.info(f"Building indicator list for query: {query}")

        try:
            scroll = None
            with tempfile.NamedTemporaryFile(mode='w+', dir='/tmp', delete=False) as tmp_file:

                #Write the start part of the MISP JSON structure
                start_str, end_str = create_greynoise_misp_json_start_end(uuid)
                tmp_file.write(start_str)

                page = 0
                write_results = 0
                while True:
                    response = session.query(query=query, scroll=scroll, exclude_raw=True, size=BATCH_SIZE, quick=False)
                    data = response.get("data", [])
                    if not data:
                        logger.error(f"GreyNoise query returned no data for query: {query}")
                        break

                    #Write paged results to a temp file to prevent out-of-memory issues
                    logger.debug(f"Writing batch {page+1} with {len(data)} results to temporary file...")
                    for item in data:
                        greynoise_json = create_greynoise_misp_object_json(item)
                        tmp_file.write(json.dumps(greynoise_json) + ",")
                    page+=1
                    write_results += len(data)

                    scroll = response.get("request_metadata", {}).get("scroll")
                    # Break if no more data (scroll returned empty in results) or max results reached
                    if not scroll or (MAX_RESULTS > 0 and BATCH_SIZE * page >= MAX_RESULTS):
                        total_count = response.get("request_metadata", {}).get("count")
                        break
                
                # Truncate the last character (assumed to be extra comma from the while loop)
                tmp_file.seek(tmp_file.tell() - 1)
                tmp_file.truncate()
                # Write the end part of the MISP JSON structure
                tmp_file.write(end_str)

            # Move the temp file to the final destination
            shutil.move(tmp_file.name, os.path.join(DATA_PATH, f"{uuid}.json"))
            logger.info(f"Finished writing {write_results} of {total_count} results to {uuid}.json")

        except Exception as e:
            logger.error(f"Error querying GreyNoise: {e}")
            traceback.print_exc()

if __name__ == "__main__":
    main()