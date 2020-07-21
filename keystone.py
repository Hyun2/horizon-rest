# Copyright 2014, Rackspace, US, Inc.
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
"""API over the keystone service."""

import copy

from django.conf import settings
import django.http
from django.views import generic

from openstack_dashboard import api
from openstack_dashboard.api.rest import urls
from openstack_dashboard.api.rest import utils as rest_utils
from openstack_dashboard.utils import identity as identity_utils
import sys
from django.http import JsonResponse


@urls.register
class Version(generic.View):
    """API for active keystone version."""
    url_regex = r'keystone/version/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get active keystone version."""
        return {'version': str(api.keystone.get_version())}


@urls.register
class Users(generic.View):
    """API for keystone users."""
    url_regex = r'keystone/users/$'
    client_keywords = {'project_id', 'domain_id', 'group_id'}

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of users.

        By default, a listing of all users for the current domain are
        returned. You may specify GET parameters for project_id, domain_id and
        group_id to change that listing's context.

        The listing result is an object with property "items".
        """
        domain_context = request.session.get('domain_context')

        filters = rest_utils.parse_filters_kwargs(request,
                                                  self.client_keywords)[0]
        if not filters:
            filters = None

        result = api.keystone.user_list(request,
                                        project=request.GET.get('project_id'),
                                        domain=request.GET.get(
                                            'domain_id', domain_context),
                                        group=request.GET.get('group_id'),
                                        filters=filters)
        return {'items': [u.to_dict() for u in result]}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Create a user.

        Create a user using the parameters supplied in the POST
        application/json object. The base parameters are name (string), email
        (string, optional), password (string), project (string,
        optional), enabled (boolean, defaults to true), description
        (string, optional). The user will be created in the default domain.

        This action returns the new user object on success.
        """
        domain = api.keystone.get_default_domain(request)

        new_user = api.keystone.user_create(
            request,
            name=request.DATA['name'],
            email=request.DATA.get('email') or None,
            password=request.DATA.get('password'),
            project=request.DATA.get('project') or None,
            enabled=request.DATA.get('enabled', True),
            description=request.DATA.get('description') or None,
            domain=domain.id)

        return rest_utils.CreatedResponse(
            '/api/keystone/users/%s' % new_user.id, new_user.to_dict())

    @rest_utils.ajax(data_required=True)
    def delete(self, request):
        """Delete multiple users by id.

        The DELETE data should be an application/json array of user ids to
        delete.

        This method returns HTTP 204 (no content) on success.
        """
        for user_id in request.DATA:
            if user_id != request.user.id:
                api.keystone.user_delete(request, user_id)


@urls.register
class User(generic.View):
    """API for a single keystone user."""
    url_regex = r'keystone/users/(?P<id>[0-9a-f]+|current)$'

    @rest_utils.ajax()
    def get(self, request, id):
        """Get a specific user by id.

        If the id supplied is 'current' then the current logged-in user
        will be returned, otherwise the user specified by the id.
        """
        if id == 'current':
            id = request.user.id
        return api.keystone.user_get(request, id, admin=False).to_dict()

    @rest_utils.ajax()
    def delete(self, request, id):
        """Delete a single user by id.

        This method returns HTTP 204 (no content) on success.
        """
        if id == 'current':
            return django.http.HttpResponseNotFound('current')
        api.keystone.user_delete(request, id)

    @rest_utils.ajax(data_required=True)
    def patch(self, request, id):
        """Update a single user.

        The PATCH data should be an application/json object with attributes to
        set to new values: password (string), project (string),
        enabled (boolean).

        A PATCH may contain any one of those attributes, but
        if it contains more than one it must contain the project, even
        if it is not being altered.

        This method returns HTTP 204 (no content) on success.
        """
        keys = tuple(request.DATA)
        user = api.keystone.user_get(request, id)

        if 'password' in keys:
            if settings.ENFORCE_PASSWORD_CHECK:
                admin_password = request.DATA['admin_password']
                if not api.keystone.user_verify_admin_password(
                        request, admin_password):
                    raise rest_utils.AjaxError(400, 'ADMIN_PASSWORD_INCORRECT')
            password = request.DATA['password']
            api.keystone.user_update_password(request, user, password)

        elif 'enabled' in keys:
            enabled = request.DATA['enabled']
            api.keystone.user_update_enabled(request, user, enabled)

        else:
            # note that project is actually project_id
            # but we can not rename due to legacy compatibility
            # refer to keystone.api user_update method
            api.keystone.user_update(request, user, **request.DATA)


@urls.register
class Roles(generic.View):
    """API over all roles."""
    url_regex = r'keystone/roles/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of roles.

        By default a listing of all roles are returned.

        If the GET parameters project_id and user_id are specified then that
        user's roles for that project are returned. If user_id is 'current'
        then the current user's roles for that project are returned.

        The listing result is an object with property "items".
        """
        project_id = request.GET.get('project_id')
        user_id = request.GET.get('user_id')
        if project_id and user_id:
            if user_id == 'current':
                user_id = request.user.id
            roles = api.keystone.roles_for_user(request, user_id,
                                                project_id) or []
            items = [r.to_dict() for r in roles]
        else:
            items = [r.to_dict() for r in api.keystone.role_list(request)]
        return {'items': items}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Create a role.

        Create a role using the "name" (string) parameter supplied in the POST
        application/json object.

        This method returns the new role object on success.
        """
        new_role = api.keystone.role_create(request, request.DATA['name'])
        return rest_utils.CreatedResponse(
            '/api/keystone/roles/%s' % new_role.id, new_role.to_dict())

    @rest_utils.ajax(data_required=True)
    def delete(self, request):
        """Delete multiple roles by id.

        The DELETE data should be an application/json array of role ids to
                delete.

        This method returns HTTP 204 (no content) on success.
        """
        for role_id in request.DATA:
            api.keystone.role_delete(request, role_id)


@urls.register
class Role(generic.View):
    """API for a single role."""
    url_regex = r'keystone/roles/(?P<id>[0-9a-f]+|default)$'

    @rest_utils.ajax()
    def get(self, request, id):
        """Get a specific role by id.

        If the id supplied is 'default' then the default role will be
        returned, otherwise the role specified by the id.
        """
        if id == 'default':
            return api.keystone.get_default_role(request).to_dict()
        return api.keystone.role_get(request, id).to_dict()

    @rest_utils.ajax()
    def delete(self, request, id):
        """Delete a single role by id.

        This method returns HTTP 204 (no content) on success.
        """
        if id == 'default':
            return django.http.HttpResponseNotFound('default')
        api.keystone.role_delete(request, id)

    @rest_utils.ajax(data_required=True)
    def patch(self, request, id):
        """Update a single role.

        The PATCH data should be an application/json object with the "name"
        attribute to update.

        This method returns HTTP 204 (no content) on success.
        """
        api.keystone.role_update(request, id, request.DATA['name'])


@urls.register
class DefaultDomain(generic.View):
    """API for default domain of the user."""
    url_regex = r'keystone/default_domain/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a default domain of the user."""
        return api.keystone.get_default_domain(request).to_dict()


@urls.register
class Domains(generic.View):
    """API over all domains."""
    url_regex = r'keystone/domains/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of domains.

        A listing of all domains are returned.

        The listing result is an object with property "items".
        """
        items = [d.to_dict() for d in api.keystone.domain_list(request)]
        return {'items': items}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Perform some action on the collection of domains.

        This action creates a domain using parameters supplied in the POST
        application/json object. The "name" (string) parameter is required,
        others are optional: "description" (string) and "enabled" (boolean,
        defaults to true).

        This method returns the new domain object on success.
        """
        new_domain = api.keystone.domain_create(
            request,
            request.DATA['name'],
            description=request.DATA.get('description'),
            enabled=request.DATA.get('enabled', True),
        )
        return rest_utils.CreatedResponse(
            '/api/keystone/domains/%s' % new_domain.id, new_domain.to_dict())

    @rest_utils.ajax(data_required=True)
    def delete(self, request):
        """Delete multiple domains by id.

        The DELETE data should be an application/json array of domain ids to
                delete.

        This method returns HTTP 204 (no content) on success.
        """
        for domain_id in request.DATA:
            api.keystone.domain_delete(request, domain_id)


@urls.register
class Domain(generic.View):
    """API over a single domains."""
    url_regex = r'keystone/domains/(?P<id>[0-9a-f]+|default)$'

    @rest_utils.ajax()
    def get(self, request, id):
        """Get a specific domain by id.

        If the id supplied is 'default' then the default domain will be
        returned, otherwise the domain specified by the id.
        """
        if id == 'default':
            return api.keystone.get_default_domain(request).to_dict()
        return api.keystone.domain_get(request, id).to_dict()

    @rest_utils.ajax()
    def delete(self, request, id):
        """Delete a single domain by id.

        This method returns HTTP 204 (no content) on success.
        """
        if id == 'default':
            return django.http.HttpResponseNotFound('default')
        api.keystone.domain_delete(request, id)

    @rest_utils.ajax(data_required=True)
    def patch(self, request, id):
        """Update a single domain.

        The PATCH data should be an application/json object with the attributes
        to set to new values: "name" (string), "description" (string) and
        "enabled" (boolean).

        This method returns HTTP 204 (no content) on success.
        """
        api.keystone.domain_update(request,
                                   id,
                                   description=request.DATA.get('description'),
                                   enabled=request.DATA.get('enabled'),
                                   name=request.DATA.get('name'))


def _tenant_kwargs_from_DATA(data, enabled=True):
    # tenant_create takes arbitrary keyword arguments with only a small
    # restriction (the default args)
    kwargs = {
        'name': None,
        'description': None,
        'enabled': enabled,
        'domain': data.pop('domain_id', None)
    }
    kwargs.update(data)
    return kwargs


@urls.register
class Projects(generic.View):
    """API over all projects.

    Note that in the following "project" is used exclusively where in the
    underlying keystone API the terms "project" and "tenant" are used
    interchangeably.
    """
    url_regex = r'keystone/projects/$'
    client_keywords = {'paginate', 'marker', 'domain_id', 'user_id', 'admin'}

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of projects.

        By default a listing of all projects for the current domain are
        returned.

        You may specify GET parameters for domain_id (string), user_id
        (string) and admin (boolean) to change that listing's context.
        Additionally, paginate (boolean) and marker may be used to get
        paginated listings.

        The listing result is an object with properties:

        items
            The list of project objects.
        has_more
            Boolean indicating there are more results when pagination is used.
        """

        filters = rest_utils.parse_filters_kwargs(request,
                                                  self.client_keywords)[0]
        if not filters:
            filters = None

        paginate = request.GET.get('paginate') == 'true'
        admin = request.GET.get('admin') != 'false'

        result, has_more = api.keystone.tenant_list(
            request,
            paginate=paginate,
            marker=request.GET.get('marker'),
            domain=request.GET.get('domain_id'),
            user=request.GET.get('user_id'),
            admin=admin,
            filters=filters)
        # return (list of results, has_more_data)
        return dict(has_more=has_more, items=[d.to_dict() for d in result])

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Create a project (tenant).

        Create a project using parameters supplied in the POST
        application/json object. The "name" (string) parameter is required,
        others are optional: "description" (string), "domain_id" (string) and
        "enabled" (boolean, defaults to true). Additional, undefined
        parameters may also be provided, but you'll have to look deep into
        keystone to figure out what they might be.

        This method returns the new project object on success.
        """
        kwargs = _tenant_kwargs_from_DATA(request.DATA)
        if not kwargs['name']:
            raise rest_utils.AjaxError(400, '"name" is required')
        new_project = api.keystone.tenant_create(request, **kwargs)
        return rest_utils.CreatedResponse(
            '/api/keystone/projects/%s' % new_project.id,
            new_project.to_dict())

    @rest_utils.ajax(data_required=True)
    def delete(self, request):
        """Delete multiple projects by id.

        The DELETE data should be an application/json array of project ids to
        delete.

        This method returns HTTP 204 (no content) on success.
        """
        for id in request.DATA:
            api.keystone.tenant_delete(request, id)


@urls.register
class Project(generic.View):
    """API over a single project.

    Note that in the following "project" is used exclusively where in the
    underlying keystone API the terms "project" and "tenant" are used
    interchangeably.
    """
    url_regex = r'keystone/projects/(?P<id>[0-9a-f]+)$'

    @rest_utils.ajax()
    def get(self, request, id):
        """Get a specific project by id."""
        return api.keystone.tenant_get(request, id, admin=False).to_dict()

    @rest_utils.ajax()
    def delete(self, request, id):
        """Delete a single project by id.

        This method returns HTTP 204 (no content) on success.
        """
        api.keystone.tenant_delete(request, id)

    @rest_utils.ajax(data_required=True)
    def patch(self, request, id):
        """Update a single project.

        The PATCH data should be an application/json object with  the
        attributes to set to new values: "name" (string),  "description"
        (string), "domain_id" (string) and "enabled" (boolean). Additional,
        undefined parameters may also be provided, but you'll have to look
        deep into keystone to figure out what they might be.

        This method returns HTTP 204 (no content) on success.
        """
        kwargs = _tenant_kwargs_from_DATA(request.DATA, enabled=None)
        api.keystone.tenant_update(request, id, **kwargs)


@urls.register
class ProjectRole(generic.View):
    url_regex = r'keystone/projects/(?P<project_id>[0-9a-f]+)/' \
                '(?P<role_id>[0-9a-f]+)/(?P<user_id>[0-9a-f]+)$'

    @rest_utils.ajax()
    def put(self, request, project_id, role_id, user_id):
        """Grant the specified role to the user in the project (tenant).

        This method takes no data.

        This method returns HTTP 204 (no content) on success.
        """
        api.keystone.add_tenant_user_role(request, project_id, user_id,
                                          role_id)

    # custom for bls
    @rest_utils.ajax()
    def delete(self, request, project_id, role_id, user_id):
        api.keystone.remove_tenant_user_role(request, project_id, user_id,
                                             role_id)


@urls.register
class ServiceCatalog(generic.View):
    url_regex = r'keystone/svc-catalog/$'

    @rest_utils.ajax()
    def get(self, request):
        """Return the service catalog associated with the current user."""
        catalog = copy.deepcopy(request.user.service_catalog)
        for record in catalog:
            for endpoint in record['endpoints']:
                if endpoint['interface'] != 'public':
                    record['endpoints'].remove(endpoint)
            if not record['endpoints']:
                catalog.remove(record)
        return catalog


@urls.register
class UserSession(generic.View):
    """API for a single keystone user."""
    url_regex = r'keystone/user-session/$'
    allowed_fields = {
        'available_services_regions', 'domain_id', 'domain_name', 'enabled',
        'id', 'is_superuser', 'project_id', 'project_name', 'roles',
        'services_region', 'user_domain_id', 'user_domain_name', 'username'
    }

    @rest_utils.ajax()
    def get(self, request):
        """Get the current user session."""
        res = {k: getattr(request.user, k, None) for k in self.allowed_fields}
        if settings.ENABLE_CLIENT_TOKEN:
            res['token'] = request.user.token.id
        return res


@urls.register
class Services(generic.View):
    """API for keystone services."""
    url_regex = r'keystone/services/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of keystone services."""
        region = request.user.services_region
        services = []
        for i, service in enumerate(request.user.service_catalog):
            services.append(
                dict(api.keystone.Service(service, region).to_dict(), id=i))

        return {'items': services}


@urls.register
class Groups(generic.View):
    """API over all groups."""
    url_regex = r'keystone/groups/$'

    @rest_utils.ajax()
    def get(self, request):
        """Get a list of groups.

        The listing result is an object with property "items".
        """
        domain_context = request.session.get('domain_context')
        items = [
            d.to_dict() for d in api.keystone.group_list(
                request, domain=request.GET.get('domain_id', domain_context))
        ]

        return {'items': items}

    @rest_utils.ajax(data_required=True)
    def post(self, request):
        """Create a group.

        This action creates a group using parameters supplied in the POST
        application/json object. The "name" (string) parameter is required,
        "description" (string) is optional.

        This method returns the new group object on success.
        """
        new_group = api.keystone.group_create(
            request, identity_utils.get_domain_id_for_operation(request),
            request.DATA['name'], request.DATA.get("description", None))

        return rest_utils.CreatedResponse(
            '/api/keystone/groups/%s' % new_group.id, new_group.to_dict())

    @rest_utils.ajax(data_required=True)
    def delete(self, request):
        """Delete multiple groups by id.

        The DELETE data should be an application/json array of group ids to
        delete.

        This method returns HTTP 204 (no content) on success.
        """
        for group_id in request.DATA:
            api.keystone.group_delete(request, group_id)


@urls.register
class Group(generic.View):
    """API over a single group."""
    url_regex = r'keystone/groups/(?P<id>[0-9a-f]+)$'

    @rest_utils.ajax()
    def get(self, request, id):
        """Get a specific group by id."""
        return api.keystone.group_get(request, id).to_dict()

    @rest_utils.ajax()
    def delete(self, request, id):
        """Delete a single group by id.

        This method returns HTTP 204 (no content) on success.
        """
        api.keystone.group_delete(request, id)

    @rest_utils.ajax(data_required=True)
    def patch(self, request, id):
        """Update a single group.

        The PATCH data should be an application/json object with the
        "name" and "description" attribute to update.

        This method returns HTTP 204 (no content) on success.
        """
        api.keystone.group_update(request, id, request.DATA['name'],
                                  request.DATA.get("description", None))


#################
# custom for bls
#################
@urls.register
class UserProjects(generic.View):
    url_regex = r'keystone/user-projects/$'

    @rest_utils.ajax()
    def get(self, request):
        # from openstack_auth.utils import get_project_list  # noqa: F403,H303

        return dict(
            items=[d.to_dict() for d in request.user.authorized_tenants])


@urls.register
class BLSProject(generic.View):
    url_regex = r'keystone/bls-projects/$'

    @rest_utils.ajax()
    def post(self, request):
        new_router, new_fip, new_project, new_network, new_subnet, new_user = (
            None, ) * 6
        try:
            company_id = request.DATA.get('company_id', None)
            create_user = request.DATA.get('create_user', None)
            user_data = request.DATA.get('user_data', None)
            subnet_cidr = request.DATA.get('subnet_cidr', None)
            horizon_uid = request.DATA.get('horizon_uid', None)
            '''
            request.DATA = {
                create_user: {{ True || False }}
                company_id: {{ company_id }},
                horizoon_uid: {{ horizon_uid }},
                user_data: {
                    name: {{ user_id }},
                    password: '',
                },
                subnet_cidr: '',
            }
            '''
            domain = api.keystone.get_default_domain(request)
            result, has_more = api.keystone.tenant_list(request,
                                                        user=horizon_uid)
            user_projects = [d.to_dict() for d in result]
            cnt_project = len(user_projects)

            # company/enable
            if create_user:
                new_project = api.keystone.tenant_create(
                    request,
                    name="default-{}".format(company_id),
                    description='')
                new_user = api.keystone.user_create(request,
                                                    project=new_project.id,
                                                    enabled=True,
                                                    domain=domain.id,
                                                    **user_data)

            # create a new project
            else:
                new_project = api.keystone.tenant_create(request,
                                                         name='{}-{}'.format(
                                                             company_id,
                                                             cnt_project),
                                                         description='')

            networks = api.neutron.network_list_for_tenant(
                request,
                tenant_id=new_project.id,
                include_external=True,
                include_pre_auto_allocate=False,
            )
            ext_nets = [
                network['id'] for network in networks
                if network['router:external']
            ]

            new_fip = api.neutron.tenant_floating_ip_allocate(
                request, tenant_id=new_project.id, pool=ext_nets[0])
            # new_fip = new_fip.to_dict()

            new_router = api.neutron.router_create(request,
                                                   external_gateway_info={
                                                       "network_id":
                                                       ext_nets[0],
                                                   },
                                                   tenant_id=new_project.id,
                                                   name="ext_router",
                                                   admin_state_up=True)

            # Availability Zones
            AZ = api.neutron.list_availability_zones(self.request, 'network',
                                                     'available')
            zones = [zone['name'] for zone in AZ]
            new_network = api.neutron.network_create(
                request,
                shared=False,
                tenant_id=new_project.id,
                name='net_int',
                admin_state_up=True,
                availability_zone_hints=zones)

            new_subnet = api.neutron.subnet_create(
                request,
                name="subnet_int",
                enable_dhcp=True,
                network_id=new_network.id,
                tenant_id=new_project.id,
                ip_version=4,
                cidr=subnet_cidr,
            )

            api.neutron.router_add_interface(request,
                                             router_id=new_router.id,
                                             subnet_id=new_subnet.id)

            if new_user:
                user_id = new_user.id
            else:
                user_id = horizon_uid

            roles = [r.to_dict() for r in api.keystone.role_list(request)]

            for role in roles:
                if role['name'] == 'member':
                    member_role = role
                elif role['name'] == 'admin':
                    admin_role = role

            api.keystone.add_tenant_user_role(request, new_project.id, user_id,
                                              member_role['id'])
            api.keystone.add_tenant_user_role(request, new_project.id,
                                              request.user.keystone_user_id,
                                              admin_role['id'])

            if new_user:
                res = {
                    "project": new_project.to_dict(),
                    "user": new_user.to_dict(),
                    "router": new_router.to_dict(),
                    "network": new_network.to_dict(),
                    "subnet": new_subnet.to_dict(),
                    "pf": new_fip.to_dict()
                }
            else:
                res = {
                    "project": new_project.to_dict(),
                    "router": new_router.to_dict(),
                    "network": new_network.to_dict(),
                    "subnet": new_subnet.to_dict(),
                    "pf": new_fip.to_dict()
                }

            return JsonResponse(res, safe=False)

        except:
            if new_router:
                api.neutron.router_remove_gateway(request, new_router.id)
                ports = api.neutron.port_list(self.request,
                                              device_id=new_router.id)
                ports_id = [port.id for port in ports if port['name'] == '']

                for port_id in ports_id:
                    api.neutron.router_remove_interface(
                        request,
                        router_id=new_router.id,
                        subnet_id=None,
                        port_id=port_id)

                api.neutron.router_delete(request, router_id=new_router.id)

            if new_subnet:
                api.neutron.subnet_delete(request, new_subnet.id)

            if new_network:
                api.neutron.network_delete(request, new_network.id)

            if new_fip:
                api.neutron.tenant_floating_ip_release(request, new_fip.id)

            if new_project:
                api.keystone.tenant_delete(request, new_project.id)

            if new_user:
                api.keystone.user_delete(request, new_user.id)

            type, value, tb = (None, ) * 3
            type, value, tb = sys.exc_info()

            if (value and value.message):
                return JsonResponse(value.message, status=400, safe=False)
            else:
                return JsonResponse("error", status=400, safe=False)


@urls.register
class DeleteBLSProject(generic.View):
    url_regex = r'keystone/bls-project/(?P<project_id>[0-9a-f]+)/$'

    @rest_utils.ajax()
    def delete(self, request, project_id):
        routers = api.neutron.router_list(request, tenant_id=project_id)
        networks = api.neutron.network_list_for_tenant(request,
                                                       tenant_id=project_id,
                                                       shared=False)

        # subnets = api.neutron.subnet_list(request, network_id=network_id)
        subnets = []
        for network in networks:
            subnets += api.neutron.subnet_list(request,
                                               network_id=network['id'])
        shared_networks = api.neutron.network_list_for_tenant(
            request, tenant_id=project_id, shared=True)
        shared_networks_ids = [network['id'] for network in shared_networks]

        for router in routers:
            for subnet in subnets:
                ports = api.neutron.port_list_with_trunk_types(
                    self.request, device_id=router['id'])

                for port in ports:
                    try:
                        api.neutron.router_remove_interface(
                            request,
                            router_id=router['id'],
                            subnet_id=subnet['id'],
                            port_id=port['id'])
                    except:
                        pass

        f_ips = api.neutron.tenant_floating_ip_list(request,
                                                    all_tenants=True,
                                                    project_id=project_id)
        f_ips = [ip.to_dict() for ip in f_ips]
        for f_ip in f_ips:
            api.neutron.floating_ip_disassociate(request, f_ip['id'])

        for router in routers:
            api.neutron.router_delete(request, router['id'])

        search_opts = {
            'project_id': project_id,
            'paginate': False,
            "all_tenants": True
        }
        servers = api.nova.server_list(request, search_opts=search_opts)[0]
        servers = [s.to_dict() for s in servers]

        for server in servers:
            api.nova.server_delete(request, server['id'])

        volumes = api.cinder.volume_list(request, search_opts=search_opts)
        volumes = [v.to_dict() for v in volumes]

        for subnet in subnets:
            api.neutron.subnet_delete(request, subnet['id'])

        for network in networks:
            if network['id'] in shared_networks_ids:
                continue
            api.neutron.network_delete(request, network['id'])

        for volume in volumes:
            api.cinder.volume_delete(request, volume['id'])

        for f_ip in f_ips:
            api.neutron.tenant_floating_ip_release(request, f_ip['id'])

        return django.http.HttpResponse(status=204)