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
from django.conf import urls
from django.conf.urls import url

from . import bls_auth

urlpatterns = [
    url(r'bls_auth/login/$', bls_auth.login),
    url(r'bls_auth/logout/$', bls_auth.bls_logout),
    url(r'bls_auth/is-admin/$', bls_auth.is_admin),
    url(r'bls_auth/token-info/$', bls_auth.get_token_info),
    url(r'bls_auth/switch/$', bls_auth.switch),
    url(r'bls_auth/is-logged-in/$', bls_auth.is_logged_in),
    url(r'bls_auth/tenant-info/$', bls_auth.tenant_info),
    url(r'bls_auth/user-info/$', bls_auth.user_info),
]

# to register the URLs for your API endpoints, decorate the view class with
# @register below, and the import the endpoint module in the
# rest_api/__init__.py module


def register(view):
    """Register API views to respond to a regex pattern.

    ``url_regex`` on a wrapped view class is used as the regex pattern.
    The view should be a standard Django class-based view implementing an
    as_view() method. The url_regex attribute of the view should be a standard
    Django URL regex pattern.
    """
    p = urls.url(view.url_regex, view.as_view())
    urlpatterns.append(p)
    return view
