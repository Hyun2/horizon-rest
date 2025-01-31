#
#    (c) Copyright 2015 Hewlett-Packard Development Company, L.P.
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
"""API over the neutron service."""

from django.utils.translation import ugettext_lazy as _
from django.views import generic

from openstack_dashboard import api
from openstack_dashboard.api.rest import urls
from openstack_dashboard.api.rest import utils as rest_utils
from openstack_dashboard.usage import quotas
from django.http import HttpResponse, JsonResponse


@urls.register
class Network(generic.View):
    url_regex = r'neutron/networks/(?P<network_id>[^/]+)/$'

    @rest_utils.ajax()
    def get(self, request, network_id):
        return api.neutron.network_get(request, network_id)

    @rest_utils.ajax()
    def delete(self, request, network_id):
        network_ports = api.neutron.port_list_with_trunk_types(
            request, network_id=network_id)

        for net_port in network_ports:
            if 'network:router' in net_port['device_owner']:
                try:
                    api.neutron.router_remove_interface(
                        request,
                        router_id=net_port['device_id'],
                        port_id=net_port['id'])
                except:
                    pass
            elif not 'network:dhcp' == net_port['device_owner']:
                try:
                    api.neutron.port_delete(request, net_port['id'])
                except:
                    pass
            # elif 'compute:nova' in net_port['device_owner']:
            #     return JsonResponse({"status": 0}, status=200, safe=False)

        network = api.neutron.network_get(request, network_id)

        for subnet in network['subnets']:
            api.neutron.subnet_delete(request, subnet['id'])

        api.neutron.network_delete(request, network_id)
        return JsonResponse({'status': 1}, status=200, safe=False)


@urls.register
class Networks(generic.View):
    """API for Neutron Networks

    https://docs.openstack.org/api-ref/network/v2/index.html
    """
    url_regex = r'neutron/networks/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of networks for a project

        The listing result is an object with property "items".  Each item is
        a network.
        """
        tenant_id = request.user.tenant_id
        # NOTE(amotoki): At now, this method is only for server create,
        # so it is no problem to pass include_pre_auto_allocate=True always.
        # We need to revisit the logic if we use this method for
        # other operations other than server create.
        result = api.neutron.network_list_for_tenant(
            request, tenant_id, include_pre_auto_allocate=True)
        return {'items': [n.to_dict() for n in result]}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Create a network

        :param  admin_state_up (optional): The administrative state of the
                network, which is up (true) or down (false).
        :param name (optional): The network name. A request body is optional:
                If you include it, it can specify this optional attribute.
        :param shared (optional): Indicates whether this network is shared
                across all tenants. By default, only administrative users can
                change this value.
        :param tenant_id (optional): Admin-only. The UUID of the tenant that
                will own the network. This tenant can be different from the
                tenant that makes the create network request. However, only
                administrative users can specify a tenant ID other than their
                own. You cannot change this value through authorization
                policies.

         :return: JSON representation of a Network
         """
        new_network = api.neutron.network_create(request, **request.DATA)
        return rest_utils.CreatedResponse(
            '/api/neutron/networks/%s' % new_network.id, new_network.to_dict())


@urls.register
class Subnets(generic.View):
    """API for Neutron Subnets

    https://docs.openstack.org/api-ref/network/v2/index.html#subnets
    """
    url_regex = r'neutron/subnets/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of subnets for a project

        The listing result is an object with property "items".  Each item is
        a subnet.

        """
        result = api.neutron.subnet_list(request, **request.GET.dict())
        return {'items': [n.to_dict() for n in result]}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Create a Subnet for a given Network

        :param name (optional):  The subnet name.
        :param network_id: The ID of the attached network.
        :param tenant_id (optional): The ID of the tenant who owns the network.
                Only administrative users can specify a tenant ID other than
                their own.
        :param allocation_pools (optional): The start and end addresses for the
                allocation pools.
        :param gateway_ip (optional): The gateway IP address.
        :param ip_version: The IP version, which is 4 or 6.
        :param cidr: The CIDR.
        :param id (optional): The ID of the subnet.
        :param enable_dhcp (optional): Set to true if DHCP is enabled and false
                if DHCP is disabled.

        :return: JSON representation of a Subnet

        """
        new_subnet = api.neutron.subnet_create(request, **request.DATA)
        return rest_utils.CreatedResponse(
            '/api/neutron/subnets/%s' % new_subnet.id, new_subnet.to_dict())


@urls.register
class Ports(generic.View):
    """API for Neutron Ports

    https://docs.openstack.org/api-ref/network/v2/index.html#ports
    """
    url_regex = r'neutron/ports/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of ports for a network

        The listing result is an object with property "items".  Each item is
        a port.
        """
        # see
        # https://github.com/openstack/neutron/blob/master/neutron/api/v2/attributes.py
        result = api.neutron.port_list_with_trunk_types(
            request, **request.GET.dict())
        return {'items': [n.to_dict() for n in result]}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        subnet_id = request.DATA['network_id']
        return api.neutron.port_create(request, **request.DATA)

    @rest_utils.ajax(data_required=True)
    def put(self, request):
        subnet_id = request.DATA['network_id']
        return api.neutron.port_update(request, subnet_id, **request.DATA)


@urls.register
class Trunk(generic.View):
    """API for a single neutron Trunk"""
    url_regex = r'neutron/trunks/(?P<trunk_id>[^/]+)/$'

    @rest_utils.ajax()
    def delete(self, request, trunk_id):
        api.neutron.trunk_delete(request, trunk_id)

    @rest_utils.ajax()
    def get(self, request, trunk_id):
        """Get a specific trunk"""
        trunk = api.neutron.trunk_show(request, trunk_id)
        return trunk.to_dict()

    @rest_utils.ajax(data_required=True)
    def patch(self, request, trunk_id):
        """Update a specific trunk"""
        old_trunk = request.DATA[0]
        new_trunk = request.DATA[1]

        return api.neutron.trunk_update(request, trunk_id, old_trunk,
                                        new_trunk)


@urls.register
class Trunks(generic.View):
    """API for neutron Trunks"""
    url_regex = r'neutron/trunks/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of trunks

        The listing result is an object with property "items".
        Each item is a trunk.
        """
        result = api.neutron.trunk_list(request, **request.GET.dict())
        return {'items': [n.to_dict() for n in result]}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        new_trunk = api.neutron.trunk_create(request, **request.DATA)
        return rest_utils.CreatedResponse(
            '/api/neutron/trunks/%s' % new_trunk.id, new_trunk.to_dict())


@urls.register
class Services(generic.View):
    """API for Neutron agents"""
    url_regex = r'neutron/agents/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of agents"""
        if api.base.is_service_enabled(request, 'network') and \
           api.neutron.is_extension_supported(request, 'agent'):
            result = api.neutron.agent_list(request, **request.GET.dict())
            return {'items': [n.to_dict() for n in result]}
        else:
            raise rest_utils.AjaxError(501, '')


@urls.register
class Extensions(generic.View):
    """API for neutron extensions."""
    url_regex = r'neutron/extensions/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of extensions.

        The listing result is an object with property "items". Each item is
        an extension.

        Example:
        http://localhost/api/neutron/extensions
        """
        result = api.neutron.list_extensions(request)
        return {'items': [e for e in result]}


class DefaultQuotaSets(generic.View):
    """API for getting default quotas for neutron"""
    url_regex = r'neutron/quota-sets/defaults/$'

    @rest_utils.ajax()
    def get(self, request):
        if api.base.is_service_enabled(request, 'network'):
            quota_set = api.neutron.tenant_quota_get(request,
                                                     request.user.tenant_id)

            result = [{
                'display_name':
                quotas.QUOTA_NAMES.get(quota.name,
                                       quota.name.replace('_', ' ').title()) +
                '',
                'name':
                quota.name,
                'limit':
                quota.limit
            } for quota in quota_set]

            return {'items': result}
        else:
            raise rest_utils.AjaxError(501, _('Service Neutron is disabled.'))


@urls.register
class QuotasSets(generic.View):
    """API for setting quotas of a given project."""
    url_regex = r'neutron/quotas-sets/(?P<project_id>[0-9a-f]+)$'

    @rest_utils.ajax(data_required=True)
    def patch(self, request, project_id):
        """Update a single project quota data.

        The PATCH data should be an application/json object with the
        attributes to set to new quota values.

        This method returns HTTP 204 (no content) on success.
        """
        # Filters only neutron quota fields
        disabled_quotas = quotas.get_disabled_quotas(request)

        if api.base.is_service_enabled(request, 'network') and \
                api.neutron.is_extension_supported(request, 'quotas'):
            neutron_data = {
                key: request.DATA[key]
                for key in quotas.NEUTRON_QUOTA_FIELDS
                if key not in disabled_quotas
            }

            api.neutron.tenant_quota_update(request, project_id,
                                            **neutron_data)
        else:
            message = _('Service Neutron is disabled or quotas extension not '
                        'available.')
            raise rest_utils.AjaxError(501, message)


@urls.register
class QoSPolicies(generic.View):
    """API for QoS Policy."""
    url_regex = r'neutron/qos_policies/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of QoS policies.

        The listing result is an object with property "items".
        Each item is a qos policy.
        """
        result = api.neutron.policy_list(request,
                                         tenant_id=request.user.project_id)
        return {'items': [p.to_dict() for p in result]}


@urls.register
class QoSPolicy(generic.View):
    """API for a single QoS Policy."""
    url_regex = r'neutron/qos_policies/(?P<policy_id>[^/]+)/$'

    @rest_utils.ajax()
    def delete(self, request, policy_id):
        api.neutron.policy_delete(request, policy_id)

    @rest_utils.ajax()
    def get(self, request, policy_id):
        """Get a specific policy"""
        policy = api.neutron.policy_get(request, policy_id)
        return policy.to_dict()


#################
# custom for bls
#################
@urls.register
class AvailabilityZones(generic.View):
    url_regex = r'neutron/availability-zones/$'

    @rest_utils.ajax()
    def get(self, request):
        return api.neutron.list_availability_zones(self.request, 'network',
                                                   'available')


@urls.register
class Routers(generic.View):
    url_regex = r'neutron/routers/$'

    @rest_utils.ajax()
    def post(self, request):
        # print(request.DATA)
        return api.neutron.router_create(request, **request.DATA)


@urls.register
class RouterAddInterface(generic.View):
    url_regex = r'neutron/routers/add-interface/$'

    @rest_utils.ajax()
    def post(self, request):
        # print(request.DATA)
        return api.neutron.router_add_interface(request, **request.DATA)


@urls.register
class SpecificProjectNetworks(generic.View):
    url_regex = r'neutron/networks/projects/(?P<project_id>[^/]+)/$'

    @rest_utils.ajax()
    def get(self, request, project_id):
        # print(request.DATA)
        result = api.neutron.network_list_for_tenant(
            request,
            project_id,
            include_external=True,
            include_pre_auto_allocate=True)
        return {'items': [n.to_dict() for n in result]}


@urls.register
class Router(generic.View):
    url_regex = r'neutron/routers/(?P<router_id>[^/]+)/$'

    @rest_utils.ajax()
    def get(self, request, router_id):
        return api.neutron.router_get(request, router_id)

    @rest_utils.ajax()
    def put(self, request, router_id):
        return api.neutron.router_update(request, router_id, **request.DATA)

    @rest_utils.ajax()
    def delete(self, request, router_id):
        return api.neutron.router_delete(request, router_id)


@urls.register
class Subnet(generic.View):
    url_regex = r'neutron/subnets/(?P<subnet_id>[^/]+)/$'

    @rest_utils.ajax()
    def get(self, request, subnet_id):
        return api.neutron.subnet_get(request, subnet_id)

    @rest_utils.ajax()
    def put(self, request, subnet_id):
        return api.neutron.subnet_update(request, subnet_id, **request.DATA)

    @rest_utils.ajax()
    def delete(self, request, subnet_id):
        # return api.neutron.port_list(self.request, device_id=router_id)
        subnet = api.neutron.subnet_get(request, subnet_id)

        network_ports = api.neutron.port_list_with_trunk_types(
            request, network_id=subnet['network_id'])

        subnet_ports = []
        router_attached_ports = []
        for net_port in network_ports:
            for fixed_ip in net_port.fixed_ips:
                if fixed_ip['subnet_id'] == subnet_id:
                    subnet_ports.append(net_port)
                    if 'network:router' in net_port['device_owner']:
                        router_id = net_port['device_id']
                        router_attached_ports.append(net_port)
                    # for removing [Detached] port
                    elif not 'network:dhcp' == net_port['device_owner']:
                        try:
                            api.neutron.port_delete(request, net_port['id'])
                        except:
                            pass
                    # elif 'compute:nova' in net_port['device_owner']:
                    #     return JsonResponse({"status": 0},
                    #                         status=200,
                    #                         safe=False)
                    break

        for router_attached_port in router_attached_ports:
            try:
                api.neutron.router_remove_interface(
                    request,
                    router_id=router_id,
                    subnet_id=subnet_id,
                    port_id=router_attached_port['id'])
            except:
                pass

        for subnet_port in subnet_ports:
            try:
                api.neutron.port_delete(request, port_id=subnet_port['id'])
            except:
                pass

        api.neutron.subnet_delete(request, subnet_id)
        return JsonResponse({"status": 1}, status=200, safe=False)


@urls.register
class RouterPorts(generic.View):
    url_regex = r'neutron/routers/(?P<router_id>[^/]+)/ports/$'

    @rest_utils.ajax()
    def get(self, request, router_id):
        # return api.neutron.port_list(self.request, device_id=router_id)
        return api.neutron.port_list_with_trunk_types(self.request,
                                                      device_id=router_id)
