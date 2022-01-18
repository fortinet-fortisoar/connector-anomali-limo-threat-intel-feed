""" 
Copyright start 
Copyright (C) 2008 - 2021 Fortinet Inc. 
All rights reserved. 
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE 
Copyright end 
""" 
import base64

import requests
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import create_file_from_string

logger = get_logger('anomali_taxii2_feed')


class TaxiiFeed(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request_taxii(self, endpoint=None, method='GET', data=None, params=None, files=None):
        try:
            if endpoint:
                url = self.server_url + 'api/v1/taxii2/feeds/' + endpoint
            else:
                url = self.server_url + 'api/v1/taxii2/feeds/'
            usr_pass = self.username + ":" + self.password
            usr_pass = usr_pass.encode()
            b64val = base64.b64encode(usr_pass)
            token = 'Basic {}'.format(b64val.decode("utf-8"))
            headers = {'Authorization': token, 'Content-Type': 'application/json'}
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 200 or response.status_code == 206:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_params(params):
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_output_schema(config, params, *args, **kwargs):
    if params.get('file_response'):
        return ({
            "md5": "",
            "sha1": "",
            "sha256": "",
            "filename": "",
            "content_length": "",
            "content_type": ""
        })
    else:
        return ({
            "id": "",
            "objects": [
                {
                    "created": "",
                    "description": "",
                    "id": "",
                    "labels": [
                    ],
                    "modified": "",
                    "name": "",
                    "object_marking_refs": [
                    ],
                    "pattern": "",
                    "type": "",
                    "valid_from": ""
                }
            ],
            "spec_version": "",
            "type": ""
        })


def get_api_root_information(config, params):
    taxii = TaxiiFeed(config)
    params = get_params(params)
    return taxii.make_request_taxii(params=params)


def get_collections(config, params):
    taxii = TaxiiFeed(config)
    params = get_params(params)
    if params:
        response = taxii.make_request_taxii(endpoint='collections/' + params['collectionID'] + '/')
    else:
        response = taxii.make_request_taxii(endpoint='collections/')
    if response.get('collections'):
        return response
    else:
        return {'collections': [response]}


def get_objects_by_collection_id(config, params):
    taxii = TaxiiFeed(config)
    params = get_params(params)
    wanted_keys = set(['added_after'])
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    response = taxii.make_request_taxii(endpoint='collections/' + params['collectionID'] + '/objects/',
                                        params=query_params)
    if params.get('file_response'):
        return create_file_from_string(contents=response, filename=params.get('filename'))
    else:
        return response


def get_objects_by_object_id(config, params):
    taxii = TaxiiFeed(config)
    params = get_params(params)
    return taxii.make_request_taxii(
        endpoint='collections/' + params['collectionID'] + '/objects/' + params['objectID'] + '/')


def get_manifest_by_collection_id(config, params):
    taxii = TaxiiFeed(config)
    params = get_params(params)
    wanted_keys = set(['added_after'])
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    return taxii.make_request_taxii(endpoint='collections/' + params['collectionID'] + '/manifest/',
                                    params=query_params)


def _check_health(config):
    try:
        params = {}
        res = get_api_root_information(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_api_root_information': get_api_root_information,
    'get_collections': get_collections,
    'get_objects_by_collection_id': get_objects_by_collection_id,
    'get_objects_by_object_id': get_objects_by_object_id,
    'get_manifest_by_collection_id': get_manifest_by_collection_id,
    'get_output_schema': get_output_schema
}
