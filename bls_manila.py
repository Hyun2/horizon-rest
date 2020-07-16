import json
import requests


class BlsNas:
    BASE = 'http://controller-vip-manage:8786/v2'
    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'X-OpenStack-Manila-API-Version': '2.51',
    }

    def __init__(self):
        pass

    def versions(self, token):
        url = '%s/' % (self.BASE)
        print(url)
        self.headers['X-Auth-Token'] = token
        return requests.get(url, headers=self.headers)

    def extend(self, token, project_id, share_id, new_size):
        url = '%s/%s/shares/%s/action' % (self.BASE, project_id, share_id)
        self.headers['X-Auth-Token'] = token
        print(new_size)
        res = requests.post(url, headers=self.headers, json=new_size)
        print(res)
        return res

    def create(self, token, project_id, params):
        url = '%s/%s/shares' % (self.BASE, project_id)
        self.headers['X-Auth-Token'] = token
        print(params)
        return requests.post(url, headers=self.headers, json={"share": params})

    def detail(self, token, project_id, share_id):
        # /v2/{project_id}/shares
        url = '%s/%s/shares/%s' % (self.BASE, project_id, share_id)
        print(url)
        self.headers['X-Auth-Token'] = token
        return requests.get(url, headers=self.headers)

    def export_locations(self, token, project_id, share_id):
        # /v2/{project_id}/shares
        url = '%s/%s/shares/%s/export_locations' % (self.BASE, project_id,
                                                    share_id)
        print(url)
        self.headers['X-Auth-Token'] = token
        return requests.get(url, headers=self.headers)

    def export_location(self, token, project_id, share_id, export_location_id):
        # /v2/{project_id}/shares
        url = '%s/%s/shares/%s/export_locations/%s' % (
            self.BASE, project_id, share_id, export_location_id)
        print(url)
        self.headers['X-Auth-Token'] = token
        return requests.get(url, headers=self.headers)

    def detail_with_export_location(self, token, project_id, share_id):
        # /v2/{project_id}/shares
        url = '%s/%s/shares/%s' % (self.BASE, project_id, share_id)
        print(url)
        self.headers['X-Auth-Token'] = token

        res = self.detail(token, project_id, share_id).json()
        res1 = self.export_locations(token, project_id, share_id).json()
        for _ in res1['export_locations']:
            if '10.21.2.201' in _['path']:
                export_location_id = _['id']
                break

        res2 = self.export_location(token, project_id, share_id,
                                    export_location_id).json()

        res['share']['export_location'] = res2['export_location']
        return res

    def list(self, token, project_id):
        # /v2/{project_id}/shares
        url = '%s/%s/shares' % (self.BASE, project_id)
        self.headers['X-Auth-Token'] = token
        return requests.get(url, headers=self.headers)

    def list_details(self, token, project_id):
        # /v2/{project_id}/shares
        print('222')
        url = '%s/%s/shares/detail' % (self.BASE, project_id)
        self.headers['X-Auth-Token'] = token
        shares = requests.get(url, headers=self.headers).json()['shares']
        print(shares)

        for share in shares:
            print(share)
            print(share['id'])
            export_locations = self.export_locations(token, project_id,
                                                     share['id']).json()
            for _ in export_locations['export_locations']:
                if '10.21.2.201' in _['path']:
                    export_location_id = _['id']
                    break
            res = self.export_location(
                token, project_id, share['id'],
                export_location_id).json()['export_location']
            print(res)
            share['export_location'] = res

        return shares

    def delete(self, token, project_id, share_id):
        # /v2.0/project_id/shares/{share_id}
        print("delete()")
        print(project_id, share_id)
        url = '%s/%s/shares/%s' % (self.BASE, project_id, share_id)
        self.headers['X-Auth-Token'] = token
        res = requests.delete(url, headers=self.headers)
        return res

    # def update(self, token, project_id, params):
    #     # /v2.0/project_id/shares/{share_id}

    #     url = '%s/%s/shares' % (self.BASE, project_id)
    #     self.headers['X-Auth-Token'] = token
    #     return requests.put(url, headers=self.headers, data=params)
