import requests
import concurrent.futures
from taxii2client.v20 import Server, as_pages
from connectors.core.connector import get_logger
from integrations.crudhub import make_request
from .constants import LOGGER_NAME, WORKER_COUNT
logger = get_logger(LOGGER_NAME)


def create_batch_records(records, create_pb_id, parent_wf, parent_step):
    url = "/api/triggers/1/notrigger/" + create_pb_id
    method = "POST"
    payload = {
        "_eval_input_params_from_env": True,
        "env": {
            "ingestedData": records
        }
    }
    if parent_wf:
        payload['parent_wf'] = parent_wf
    if parent_step:
        payload['parent_id'] = parent_step
    make_request(url, method, body=payload)


def insert_collection(collection, create_pb_id, parent_wf, parent_step):
    logger.info("started processing collection: %s" % collection.title)
    for bundle in as_pages(collection.get_objects, per_request=1000):
        data = bundle["objects"]
        create_batch_records(data, create_pb_id, parent_wf, parent_step)
    logger.info("done processing collection: %s" % collection.title)
    return("ingestion complete for collection: %s" % collection.title)


def get_feed(config, params, *args, **kwargs):
    serverURL = config.get("serverURL", "https://limo.anomali.com/api/v1/taxii2/taxii/")
    user = config.get("username", "guest")
    password = config.get("password", "guest")
    create_pb_id = params.get("create_pb_id")
    parent_wf = kwargs.get("env", {}).get("wf_id")
    parent_step = kwargs.get("env", {}).get("step_id")
    server = Server(serverURL, user=user, password=password)
    api_root = server.api_roots[0]
    results = []
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
        for collection in api_root.collections:
            futures.append(executor.submit(insert_collection, collection=collection, create_pb_id=create_pb_id, parent_wf=parent_wf, parent_step=parent_step))
    for future in concurrent.futures.as_completed(futures):
        results.append(future.result())
    return results
    # 