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
    url_regex = r'manila/shares/versions/$'

    nas = bls_manila.BlsNas()

    def get(self, request):
        return JsonResponse(self.nas.versions(request.user.token.id).json(),
                            safe=False)


@urls.register
class Shares(generic.View):
    url_regex = r'manila/shares/(?P<project_id>[^/]+)/$'

    nas = bls_manila.BlsNas()

    def get(self, request, project_id):
        print(project_id)
        return JsonResponse(self.nas.list(request.user.token.id,
                                          project_id).json(),
                            safe=False)

    @rest_utils.ajax()
    def post(self, request, project_id):
        pass

    @rest_utils.ajax()
    def put(self, request, project_id):
        pass

    @rest_utils.ajax()
    def delete(self, request, project_id):
        pass
