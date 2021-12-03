from integrations.crudhub import make_request
from connectors.core.connector import get_logger

logger = get_logger('anomali-limo-threat-intel-feed')


def create_batch_records(records, create_pb_id, parent_wf, parent_step):
    try:
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
            payload['step_id'] = parent_step
        make_request(url, method, body=payload)
    except Exception as e:
        logger.error("Failed to insert a batch of feeds with error: " + str(e))