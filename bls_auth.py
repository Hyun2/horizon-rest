from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth import views as django_auth_views
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.utils import functional
from openstack_auth import forms
import json
from django.conf import settings
from openstack_auth import utils
from openstack_auth import user as auth_user
from django.contrib import messages
from django.http import JsonResponse
from keystoneauth1 import exceptions as keystone_exceptions
import datetime
import logging
LOG = logging.getLogger(__name__)


class APILoginView(django_auth_views.LoginView):
    '''A LoginView with no CSRF protection.'''
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(django_auth_views.LoginView,
                     self).dispatch(request, *args, **kwargs)


@csrf_exempt
def login(request):
    if request.method == "POST":
        # print(request.POST)
        data = json.loads(request.body)
        data['region'] = 'default'
        data['domain'] = 'default'
        request.POST = data

        APILoginView.as_view(template_name='',
                             redirect_field_name=auth.REDIRECT_FIELD_NAME,
                             form_class=functional.curry(forms.Login),
                             extra_context={},
                             redirect_authenticated_user=False)(request)

        if request.user.is_authenticated:
            # print("is_authenticated")
            auth_user.set_session_from_user(request, request.user)
            regions = dict(forms.get_region_choices())
            region = request.user.endpoint
            login_region = request.POST.get('region')
            region_name = regions.get(login_region)
            request.session['region_endpoint'] = region
            request.session['region_name'] = region_name
            expiration_time = request.user.time_until_expiration()
            threshold_days = settings.PASSWORD_EXPIRES_WARNING_THRESHOLD_DAYS
            if (expiration_time is not None
                    and expiration_time.days <= threshold_days
                    and expiration_time > datetime.timedelta(0)):
                expiration_time = str(expiration_time).rsplit(':', 1)[0]
                msg = (
                    _('Please consider changing your password, it will expire'
                      ' in %s minutes') % expiration_time).replace(
                          ':', ' Hours and ')
                messages.warning(request, msg)
        else:
            return JsonResponse("Password is wrong. Ensure your password.",
                                safe=False)

        res = dict(
            items=[d.to_dict() for d in request.user.authorized_tenants])

        for project in res['items']:
            if project['name'] == 'admin':
                break
        switch(request, project['id'])

        print(request.session.session_key)
        return JsonResponse(request.session.session_key, safe=False)
    else:
        print('GET request')
        return JsonResponse("GET response", safe=False)


@login_required
def switch(request, project_id=None):
    if not project_id:
        data = json.loads(request.body)
        tenant_id = data['project_id']
    else:
        tenant_id = project_id
    LOG.debug('Switching to tenant %s for user "%s".', tenant_id,
              request.user.username)

    endpoint, __ = utils.fix_auth_url_version_prefix(request.user.endpoint)
    session = utils.get_session()

    unscoped_token = request.user.unscoped_token
    auth = utils.get_token_auth_plugin(auth_url=endpoint,
                                       token=unscoped_token,
                                       project_id=tenant_id)

    try:
        auth_ref = auth.get_access(session)
        msg = 'Project switch successful for user "%(username)s".' % \
            {'username': request.user.username}
        LOG.info(msg)
    except keystone_exceptions.ClientException:
        msg = (_('Project switch failed for user "%(username)s".') % {
            'username': request.user.username
        })
        messages.error(request, msg)
        auth_ref = None
        LOG.exception('An error occurred while switching sessions.')

    if auth_ref:
        user = auth_user.create_user_from_token(
            request, auth_user.Token(auth_ref, unscoped_token=unscoped_token),
            endpoint)
        auth_user.set_session_from_user(request, user)
        message = (_('Switch to project "%(project_name)s" successful.') % {
            'project_name': request.user.project_name
        })
        messages.success(request, message)
        # utils.set_response_cookie(response, 'recent_project',
        #                           request.user.project_id)
        return JsonResponse("success", safe=False)

    else:
        return JsonResponse("failed", safe=False)


def is_admin(request):
    if request.method == "POST":
        print('POST request')
        return JsonResponse("POST response", safe=False)
    else:
        if request.user.is_superuser:
            print("isadmin: True")
            return JsonResponse(True, safe=False)
        else:
            print("isadmin: False")
            return JsonResponse(False, safe=False)


@login_required
def get_token_info(request):
    if request.method == "POST":
        print('POST request')
        return JsonResponse("POST response", safe=False)
    else:
        if request.user.is_authenticated:
            # print(request.user)
            data = {
                "username": request.user.username,
                "token_expires": request.user.token.expires,
                "token_user": request.user.token.user,
                "token_project": request.user.token.project
            }

            return JsonResponse(data, safe=False)
        else:
            return JsonResponse("not logged in", safe=False)


def is_logged_in(request):
    if request.user.is_authenticated:
        return JsonResponse(True, safe=False)
    else:
        return JsonResponse(False, safe=False)