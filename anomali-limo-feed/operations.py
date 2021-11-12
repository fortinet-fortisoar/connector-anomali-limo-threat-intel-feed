""" 
Copyright start 
Copyright (C) 2008 - 2021 Fortinet Inc. 
All rights reserved. 
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE 
Copyright end 
"""
import base64

import requests
from connectors.cyops_utilities.builtins import create_file_from_string
from taxii2client.v20 import Collection, as_pages
from taxii2client.v21 import Collection, as_pages

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('anomali-limo-threat-feed')


class TaxiiClient(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request_taxii(self, endpoint=None, method='GET', data=None, params=None, files=None, headers=None):
        try:
            if endpoint:
                url = self.server_url + 'api/v1/taxii2/feeds/' + endpoint
            else:
                url = self.server_url + 'api/v1/taxii2/feeds/'
            usr_pass = self.username + ":" + self.password
            usr_pass = usr_pass.encode()
            b64val = base64.b64encode(usr_pass)
            token = 'Basic {}'.format(b64val.decode("utf-8"))
            default_params = {'match[type]': 'indicator'}
            params = {**default_params, **params} if params is not None and params != '' else default_params
            default_header = {'Authorization': token, 'Content-Type': 'application/json'}
            headers = {**default_header, **headers} if headers is not None and headers != '' else default_header
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl, timeout=120)
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
    taxii = TaxiiClient(config)
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return taxii.make_request_taxii(params=params)


def get_collections(config, params):
    taxii = TaxiiClient(config)
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    if params:
        response = taxii.make_request_taxii(endpoint='collections/' + params['collectionID'] + '/')
    else:
        response = taxii.make_request_taxii(endpoint='collections/')
    if response.get('collections'):
        return response
    else:
        return {'collections': [response]}


def get_objects_by_collection_id(config, params):
    taxii = TaxiiClient(config)
    if params.get('limit') is None or params.get('limit') == '':
        server_url = config.get('server_url')
        if not server_url.startswith('https://'):
            server_url = 'https://' + server_url
        if not server_url.endswith('/'):
            server_url += '/'
        username = config.get('username')
        password = config.get('password')
        collection = Collection(
            server_url + 'api/v1/taxii2/feeds/collections/' + str(params.get('collectionID')) + '/',
            user=username, password=password)
        response = []
        for bundle in as_pages(collection.get_objects, added_after=params.get('added_after') if (
                params.get('added_after') is not None and params.get(
            'added_after') != '') else '1970-01-01T00:00:00.000Z', start=params.get('offset'),
                               per_request=1000):
            response.append(bundle)
    else:
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        wanted_keys = set(['added_after'])
        query_params = {k: params[k] for k in params.keys() & wanted_keys}
        headers = {'Range': 'items {0}-{1}'.format(str(params.get('offset')), str(params.get('limit') - 1))}
        response = taxii.make_request_taxii(endpoint='collections/' + str(params.get('collectionID')) + '/objects/',
                                            params=query_params, headers=headers)
    if params.get('file_response'):
        return create_file_from_string(contents=response, filename=params.get('filename'))
    else:
        return response


def get_objects_by_object_id(config, params):
    taxii = TaxiiClient(config)
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return taxii.make_request_taxii(
        endpoint='collections/' + params['collectionID'] + '/objects/' + params['objectID'] + '/')


def get_manifest_by_collection_id(config, params):
    taxii = TaxiiClient(config)
    params = {k: v for k, v in params.items() if v is not None and v != ''}
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
        logger.exception('{0}'.format(e))


operations = {
    'get_api_root_information': get_api_root_information,
    'get_collections': get_collections,
    'get_objects_by_collection_id': get_objects_by_collection_id,
    'get_objects_by_object_id': get_objects_by_object_id,
    'get_manifest_by_collection_id': get_manifest_by_collection_id,
    'get_output_schema': get_output_schema
}
