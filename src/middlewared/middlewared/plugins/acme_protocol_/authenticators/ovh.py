import hashlib
import json
import logging
import time
from urllib.parse import urlencode

import requests

from middlewared.api.base.types.cloud import OVH_ENDPOINTS
from middlewared.api.current import OVHSchemaArgs

from .base import Authenticator


logger = logging.getLogger(__name__)


class _OVHClient:
    """Minimal OVH DNS API client for ACME TXT challenge records."""

    def __init__(self, endpoint, application_key, application_secret, consumer_key, ttl):
        self.endpoint_api = OVH_ENDPOINTS[endpoint]
        self.application_key = application_key
        self.application_secret = application_secret
        self.consumer_key = consumer_key
        self.ttl = ttl
        self.session = requests.Session()
        self._time_delta = None

    def _sync_time(self):
        if self._time_delta is None:
            server_time = self.session.get(f'{self.endpoint_api}/auth/time').json()
            self._time_delta = server_time - int(time.time())
        return self._time_delta

    def _request(self, method, path, data=None, params=None):
        time_delta = self._sync_time()
        url = self.endpoint_api + path
        body = json.dumps(data) if data is not None else ''
        timestamp = str(int(time.time()) + time_delta)
        signed_url = f'{url}?{urlencode(params)}' if params else url
        signature_payload = '+'.join([
            self.application_secret, self.consumer_key, method.upper(),
            signed_url, body, timestamp,
        ]).encode('utf-8')
        headers = {
            'X-Ovh-Application': self.application_key,
            'X-Ovh-Consumer': self.consumer_key,
            'X-Ovh-Timestamp': timestamp,
            'X-Ovh-Signature': '$1$' + hashlib.sha1(signature_payload).hexdigest(),
        }
        if data is not None:
            headers['Content-type'] = 'application/json'
        response = self.session.request(method, url, params=params, data=body, headers=headers)
        response.raise_for_status()
        return response.json() if response.text else None

    @staticmethod
    def _relative_name(domain, fqdn):
        name = fqdn.rstrip('.').lower()
        zone = domain.rstrip('.').lower()
        if name.endswith(zone):
            name = name[:-len(zone)].rstrip('.')
        return name

    def _find_record_ids(self, domain, sub_domain, content):
        record_ids = self._request(
            'GET', f'/domain/zone/{domain}/record',
            params={'fieldType': 'TXT', 'subDomain': sub_domain},
        ) or []
        return [
            record_id for record_id in record_ids
            if (record := self._request('GET', f'/domain/zone/{domain}/record/{record_id}'))
            and record.get('target') == content
        ]

    def add_txt_record(self, domain, validation_name, validation_content):
        sub_domain = self._relative_name(domain, validation_name)
        if self._find_record_ids(domain, sub_domain, validation_content):
            return
        self._request('POST', f'/domain/zone/{domain}/record', data={
            'fieldType': 'TXT', 'subDomain': sub_domain,
            'target': validation_content, 'ttl': self.ttl,
        })
        self._request('POST', f'/domain/zone/{domain}/refresh')

    def del_txt_record(self, domain, validation_name, validation_content):
        sub_domain = self._relative_name(domain, validation_name)
        for record_id in self._find_record_ids(domain, sub_domain, validation_content):
            self._request('DELETE', f'/domain/zone/{domain}/record/{record_id}')
        self._request('POST', f'/domain/zone/{domain}/refresh')


class OVHAuthenticator(Authenticator):

    NAME = 'OVH'
    PROPAGATION_DELAY = 60
    SCHEMA_MODEL = OVHSchemaArgs

    def initialize_credentials(self):
        self.application_key = self.attributes.get('application_key')
        self.application_secret = self.attributes.get('application_secret')
        self.consumer_key = self.attributes.get('consumer_key')
        self.endpoint = self.attributes.get('endpoint')

    @staticmethod
    async def validate_credentials(middleware, data):
        return data

    def _perform(self, domain, validation_name, validation_content):
        self.get_client().add_txt_record(domain, validation_name, validation_content)

    def get_client(self):
        return _OVHClient(
            self.endpoint, self.application_key, self.application_secret,
            self.consumer_key, 600,
        )

    def _cleanup(self, domain, validation_name, validation_content):
        self.get_client().del_txt_record(domain, validation_name, validation_content)
