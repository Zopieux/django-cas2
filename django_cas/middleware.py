""" Django CAS 2.0 authentication middleware """

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.views import login, logout
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import resolve
from django.http import HttpResponseRedirect
from django.utils.http import urlquote_plus
from django_cas.exceptions import CasTicketException
from django_cas.views import login as cas_login, logout as cas_logout
from urllib import urlencode
import base64
import hashlib


__all__ = ['CASMiddleware']


class CASMiddleware(object):
    """Middleware that allows CAS authentication on admin pages"""

    def process_request(self, request):
        """ Checks that the authentication middleware is installed. """

        error = ("The Django CAS middleware requires authentication "
                 "middleware to be installed. Edit your MIDDLEWARE_CLASSES "
                 "setting to insert 'django.contrib.auth.middleware."
                 "AuthenticationMiddleware'.")
        assert hasattr(request, 'user'), error

    def process_view(self, request, view_func, view_args, view_kwargs):
        """ Forwards unauthenticated requests to the admin page to the CAS
            login URL, as well as calls to django.contrib.auth.views.login and
            logout.
        """
        if view_func == login:
            return cas_login(request, *view_args, **view_kwargs)
        if view_func == logout:
            return cas_logout(request, *view_args, **view_kwargs)
        
        # The rest of this method amends the Django admin authorization wich
        # will post a username/password dialog to authenticate to django admin.
        if not view_func.__module__.startswith('yawdadmin.'):
            return None

        if request.user.is_authenticated():
            if request.user.is_staff:
                return None
            else:
                raise PermissionDenied("No staff priviliges")
        params = urlencode({auth.REDIRECT_FIELD_NAME: request.get_full_path()})        
        return HttpResponseRedirect(settings.LOGIN_URL + '?' + params)

    def process_exception(self, request, exception):
        """ When we get a CasTicketException it is probably caused by the ticket timing out.
            So logout and get the same page again."""
        if isinstance(exception, CasTicketException):
            auth.logout(request)
            return HttpResponseRedirect(request.path)
        else:
            return None


class CASLoginMiddleware(object):
    def process_request(self, request):
        if request.method == 'GET' and not request.user.is_authenticated() and 'elorus_cas' in request.COOKIES and request.COOKIES['elorus_cas'] == self.hash_value('login'):
            current_view = resolve(request.path)[0]
            if not hasattr(current_view, 'func_name') or current_view.func_name not in  ('login', 'logout'):
                return HttpResponseRedirect('%s?next=%s' % (settings.LOGIN_URL, urlquote_plus(request.get_full_path())))
        elif request.method == 'GET' and request.user.is_authenticated() and 'elorus_cas' in request.COOKIES and request.COOKIES['elorus_cas'] == self.hash_value('logout'):
            current_view = resolve(request.path)[0]
            if not hasattr(current_view, 'func_name') or current_view.func_name not in  ('login', 'logout'):
                return HttpResponseRedirect('%s?next=%s' % (settings.LOGOUT_URL, urlquote_plus(request.get_full_path())))

    def process_response(self, request, response):
        if hasattr(request, 'user') and request.user.is_authenticated() and not 'elorus_cas' in request.COOKIES:
            #by default the cookie expires when the session is over.. so.. perfect!
            response.set_cookie(key='elorus_cas', value=self.hash_value('login'), domain=settings.ELEP_DOMAIN, max_age=request.session.get_expiry_age(), httponly=True)
        elif (not hasattr(request, 'user') or not request.user.is_authenticated()) and 'elorus_cas' in request.COOKIES and request.COOKIES['elorus_cas'] == self.hash_value('login'):
            try:
                current_view = resolve(request.path)[0]
            except:
                pass
            else:
                if hasattr(current_view, 'func_name') and current_view.func_name == 'logout':
                    response.set_cookie(key='elorus_cas', value=self.hash_value('logout'), domain=settings.ELEP_DOMAIN)
        elif hasattr(request, 'user') and request.user.is_authenticated() and 'elorus_cas' in request.COOKIES and request.COOKIES['elorus_cas'] == self.hash_value('logout'):
            try:
                current_view = resolve(request.path)[0]
            except:
                pass
            else:
                if hasattr(current_view, 'func_name') and current_view.func_name == 'login':
                    response.set_cookie(key='elorus_cas', value=self.hash_value('login'), domain=settings.ELEP_DOMAIN, max_age=request.session.get_expiry_age())
        return response

    def hash_value(self, value):
        m = hashlib.md5()
        m.update(value)
        return base64.b64encode(m.digest())
