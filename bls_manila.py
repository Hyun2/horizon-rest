import json
import requests


class BlsNas:
    BASE = 'http://controller-vip-manage:8786/v2'

    def __init__(self):
        pass

    def create(self, token, project_id):
        url = '%s/%s/port_forwardings' % (self.BASE, project_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }
        return requests.post(url, headers=headers)

    def list(self, token, project_id):
        # /v2/{project_id}/shares
        url = '%s/%s/shares' % (self.BASE, project_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token,
            'X-OpenStack-Manila-API-Version': '2.10'
        }
        return requests.get(url, headers=headers)

    def delete(self, token, project_id, port_forwarding_id):
        # /v2.0/floatingips/{floatingip_id}/port_forwardings/{port_forwarding_id}
        url = '%s/%s/port_forwardings/%s' % (self.BASE, project_id,
                                             port_forwarding_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }
        return requests.delete(url, headers=headers)

    def update(self, token, project_id, params):
        # /v2.0/floatingips/{floatingip_id}/port_forwardings/{port_forwarding_id}

        url = '%s/%s/port_forwardings' % (self.BASE, project_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }
        return requests.put(url, headers=headers, data=params)