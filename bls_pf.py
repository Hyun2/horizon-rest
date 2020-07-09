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


#pf = BlsPortForwarding()
#params = {'id': '958178d0-a255-4414-b1ec-ed8495723d79'}
#pf.list("gAAAAABe5zmds0q7DVaikhqHQFivAXSKTL39HeVSGZXX1nmJW4MP5ut2IN_cwVGdZtuyyNe_d5rFcM9P2PBkv3ym_CtxFypOmok1sro2wwHiE9MSff7sOFvBCTx_MqQDtLNxCipkp8nss5z77JBKts_P8vlSvMZVf1-KrqNMcFnvihPeS3tN77w",params)
