from django.views import generic

from openstack_dashboard import api
from openstack_dashboard.api.rest import urls
from openstack_dashboard.api.rest import utils as rest_utils
import json
from django.http import HttpResponse
from django.http import JsonResponse

from . import bls_manila


@urls.register
class Share(generic.View):
    url_regex = r'manila/(?P<project_id>[^/]+)/shares/(?P<share_id>[^/]+)/$'

    nas = bls_manila.BlsNas()

    @rest_utils.ajax()
    def delete(self, request, project_id, share_id):
        return self.nas.delete(request.user.token.id, project_id, share_id)


@urls.register
class Shares(generic.View):
    url_regex = r'manila/(?P<project_id>[^/]+)/shares/$'

    nas = bls_manila.BlsNas()

    @rest_utils.ajax()
    def post(self, request, project_id):
        params = request.DATA
        params['share_proto'] = "NFS"
        # params['share_type'] = "default_share_type"
        share = self.nas.create(request.user.token.id, project_id,
                                params).json()
        print(share)

        return JsonResponse(self.nas.detail_with_export_location(
            request.user.token.id, project_id, share['share']['id']),
                            safe=False)

    @rest_utils.ajax()
    def get(self, request, project_id):
        return JsonResponse(self.nas.list_details(request.user.token.id,
                                                  project_id),
                            safe=False)


@urls.register
class ShareExtend(generic.View):
    url_regex = r'manila/(?P<project_id>[^/]+)/shares/(?P<share_id>[^/]+)/extend/$'

    nas = bls_manila.BlsNas()

    @rest_utils.ajax()
    def post(self, request, project_id, share_id):
        # request.DATA['new_size']
        print(request.DATA['data'])
        res = self.nas.extend(request.user.token.id, project_id, share_id,
                              request.DATA['data'])
        return res


@urls.register
class ShareWithExportInfo(generic.View):
    url_regex = r'manila/(?P<project_id>[^/]+)/shares/(?P<share_id>[^/]+)/export/$'

    nas = bls_manila.BlsNas()

    @rest_utils.ajax()
    def get(self, request, project_id, share_id):
        return JsonResponse(self.nas.detail_with_export_location(
            request.user.token.id, project_id, share_id),
                            safe=False)


@urls.register
class Rules(generic.View):
    url_regex = r'manila/(?P<project_id>[^/]+)/share-access-rules/(?P<share_id>[^/]+)/$'

    nas = bls_manila.BlsNas()

    @rest_utils.ajax()
    def get(self, request, project_id, share_id):
        return JsonResponse(self.nas.get_rules(request.user.token.id,
                                               project_id, share_id),
                            safe=False)


@urls.register
class manageRule(generic.View):
    url_regex = r'manila/(?P<project_id>[^/]+)/shares/(?P<share_id>[^/]+)/action/$'

    nas = bls_manila.BlsNas()

    @rest_utils.ajax()
    def post(self, request, project_id, share_id):
        params = request.DATA
        params['access_type'] = 'ip'
        # return {}
        return JsonResponse(self.nas.create_rule(request.user.token.id,
                                                 project_id, share_id, params),
                            safe=False)

    @rest_utils.ajax()
    def delete(self, request, project_id, share_id):
        params = request.DATA
        # params['access_type'] = 'ip'
        # return {}
        return self.nas.delete_rule(request.user.token.id, project_id,
                                    share_id, params)


# @urls.register
# class SharesDetails(generic.View):
#     url_regex = r'manila/(?P<project_id>[^/]+)/shares/detail/$'

#     nas = bls_manila.BlsNas()

#     @rest_utils.ajax()
#     def get(self, request, project_id):
#         return JsonResponse(self.nas.list_details(request.user.token.id,
#                                                   project_id),
#                             safe=False)
