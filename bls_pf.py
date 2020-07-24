import json
import requests


class BlsPortForwarding:
    BASE = 'http://controller-vip-manage:9696/v2.0/floatingips'

    def __init__(self):
        pass

    def create(self, token, floating_ip_id, params):
        '''
        /v2.0/floatingips/{floatingip_id}/port_forwardings
        {
            "port_forwarding": {
              "protocol": "tcp",
              "internal_ip_address": "10.0.0.11",
              "internal_port": 25,
              "internal_port_id": "1238be08-a2a8-4b8d-addf-fb5e2250e480",
              "external_port": 2230,
              "description": "Some description"
            }
        }
        '''

        url = '%s/%s/port_forwardings' % (self.BASE, floating_ip_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }
        return requests.post(url, headers=headers, json=params)

    def list(self, token, floating_ip_id):
        # /v2.0/floatingips/{floatingip_id}/port_forwardings
        url = '%s/%s/port_forwardings' % (self.BASE, floating_ip_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }
        return requests.get(url, headers=headers)

    def pf_list_of_ip_list(self, token, fip_list):
        # /v2.0/floatingips/{floatingip_id}/port_forwardings
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }

        result = []
        for fip in fip_list:
            url = '%s/%s/port_forwardings' % (self.BASE, fip['id'])

            pf_list = requests.get(url,
                                   headers=headers).json()['port_forwardings']
            if pf_list:
                for pf in pf_list:
                    pf['fip'] = fip['ip']
            result += pf_list
            # if pf:
            #     result.append({"fip": fip['ip'], "pf": pf})

        return result

    def delete(self, token, floating_ip_id, port_forwarding_id):
        # /v2.0/floatingips/{floatingip_id}/port_forwardings/{port_forwarding_id}
        url = '%s/%s/port_forwardings/%s' % (self.BASE, floating_ip_id,
                                             port_forwarding_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }
        return requests.delete(url, headers=headers)

    def update(self, token, floating_ip_id, params):
        # /v2.0/floatingips/{floatingip_id}/port_forwardings/{port_forwarding_id}
        '''
        {
            "port_forwarding": {
                "protocol": "udp",
                "internal_port": 37,
                "internal_port_id": "99889dc2-19a7-4edb-b9d0-d2ace8d1e144",
                "external_port": 1960,
                "description": "Some description"
            }
        }
        '''

        url = '%s/%s/port_forwardings' % (self.BASE, floating_ip_id)
        headers = {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Auth-Token': token
        }
        return requests.put(url, headers=headers, data=params)

    def show(token, floating_ip_id):
        # /v2.0/floatingips/{floatingip_id}/port_forwardings/{port_forwarding_id}
        pass