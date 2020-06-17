
# Copyright 2015, Hewlett-Packard Development Company, L.P.
# Copyright 2016 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""API for the network abstraction APIs."""

from django.views import generic

from openstack_dashboard import api
from openstack_dashboard.api.rest import urls
from openstack_dashboard.api.rest import utils as rest_utils
import json
import bls_pf
from django.http import HttpResponse


@urls.register
class SecurityGroups(generic.View):
    """API for Network Abstraction

    Handles differences between Nova and Neutron.
    """
    url_regex = r'network/securitygroups/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of security groups.

        The listing result is an object with property "items". Each item is
        a security group.

        Example GET:
        http://localhost/api/network/securitygroups
        """

        security_groups = api.neutron.security_group_list(request)

        return {'items': [sg.to_dict() for sg in security_groups]}

    # custom for bls
    @rest_utils.ajax()
    def post(self, request):
        data = json.loads(request.body)
        return api.neutron.security_group_create(request, **data)


@urls.register
class FloatingIP(generic.View):
    """API for a single floating IP address."""
    url_regex = r'network/floatingip/$'

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Allocate a new floating IP address.

        :param pool_id: The ID of the floating IP address pool in which to
                        allocate the new address.

        :return: JSON representation of the new floating IP address
        """
        pool = request.DATA['pool_id']
        params = {}
        if 'dns_domain' in request.DATA:
            params['dns_domain'] = request.DATA['dns_domain']
        if 'dns_name' in request.DATA:
            params['dns_name'] = request.DATA['dns_name']
        result = api.neutron.tenant_floating_ip_allocate(request, pool,
                                                         None, **params)
        return result.to_dict()

    @rest_utils.ajax(data_required=True)
    def patch(self, request):
        """Associate or disassociate a floating IP address.

        :param address_id: The ID of the floating IP address to associate
                           or disassociate.
        :param port_id: The ID of the port to associate.
        """
        address = request.DATA['address_id']
        port = request.DATA.get('port_id')
        if port is None:
            api.neutron.floating_ip_disassociate(request, address)
        else:
            api.neutron.floating_ip_associate(request, address, port)


@urls.register
class FloatingIPs(generic.View):
    """API for floating IP addresses."""
    url_regex = r'network/floatingips/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of floating IP addresses.

        The listing result is an object with property "items". Each item is
        an extension.

        Example:
        http://localhost/api/network/floatingips
        """

        print(request)

        result = api.neutron.tenant_floating_ip_list(request)
        return {'items': [ip.to_dict() for ip in result]}

@urls.register
class FloatingIPPools(generic.View):
    """API for floating IP pools."""
    url_regex = r'network/floatingippools/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of floating IP pools.

        The listing result is an object with property "items". Each item is
        an extension.

        Example:
        http://localhost/api/network/floatingippools
        """
        result = api.neutron.floating_ip_pools_list(request)
        return {'items': [p.to_dict() for p in result]}

def get_auth_params_from_request(request):
    return (request.user.token.id)
    

@urls.register
class FloatingIPPortForwadings(generic.View):
    """API for floating IP portForwardings."""
    url_regex = r'network/port_forwarding/(?P<floating_ip_id>[^/]+)/$'
    
    pf = bls_pf.BlsPortForwarding()
    
    #@rest_utils.ajax()
    def get(self, request,floating_ip_id):
        return HttpResponse(json.loads(request))
        #return self.pf.list(get_auth_params_from_request(request),floating_ip_id)
    

##################
# cumstom for bls
##################
@urls.register
class SecurityGroup(generic.View):
    url_regex = r'network/securitygroup/(?P<sg_id>[^/]+)/$'

    @rest_utils.ajax()
    def get(self, request, sg_id):
        # print(sg_id)
        return api.neutron.security_group_get(request, sg_id)

    @rest_utils.ajax()
    def delete(self, request, sg_id):
        # print(sg_id)
        return api.neutron.security_group_delete(request, sg_id)


@urls.register
class SecurityGroupRules(generic.View):
    url_regex = r'network/securitygroup/(?P<sg_id>[^/]+)/rules/$'

    @rest_utils.ajax()
    def get(self, request, sg_id):
        # print(sg_id)
        return api.neutron.security_group_get(request, sg_id)['rules']


@urls.register
class AddSecurityGroupRule(generic.View):
    url_regex = r'network/securitygroup/(?P<sg_id>[^/]+)/add_rule/$'

    @rest_utils.ajax()
    def post(self, request, sg_id):
        data = json.loads(request.body)
        # ethertype: IPv4
        data['ethertype'] = 'IPv4'
        return api.neutron.security_group_rule_create(request, parent_group_id=sg_id, **data)


@urls.register
class DeleteSecurityGroupRule(generic.View):
    url_regex = r'network/securitygroup-rule/(?P<sgr_id>[^/]+)/$'

    @rest_utils.ajax()
    def delete(self, request, sgr_id):
        return api.neutron.security_group_rule_delete(request, sgr_id)


@urls.register
class ReleaseFloatingIP(generic.View):
    url_regex = r'network/floatingip/(?P<floating_ip_id>[^/]+)/$'

    @rest_utils.ajax()
    def delete(self, request, floating_ip_id):
        return api.neutron.tenant_floating_ip_release(request, floating_ip_id)