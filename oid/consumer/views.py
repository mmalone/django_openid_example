import urllib
from oid.store.models import DjangoOpenIDStore
from openid.consumer import consumer
from openid.consumer.discover import DiscoveryFailure
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext


def get_consumer(request):
    """
    Get a Consumer object to perform OpenID authentication.
    """
    return consumer.Consumer(request.session, DjangoOpenIDStore())


def login(request):
    """
    Start the OpenID authentication process.
    """
    if request.POST:
        # Start OpenID authentication.
        openid_url = request.POST.get('openid_identifier', '')
        auth_consumer = get_consumer(request)

        try:
            auth_request = auth_consumer.begin(openid_url)
        except DiscoveryFailure, ex:
            # Some protocol-level failure occurred.
            error = "OpenID discovery error: %s" % (ex,)
            return HttpResponseRedirect('%s?%s' % (reverse('openid_login'), urllib.urlencode({'error': error})))

        if request.is_secure():
            realm = 'https://%s' % (request.get_host(),)
        else:
            realm = 'http://%s' % (request.get_host(),)
        return_to = request.build_absolute_uri(reverse('openid_finish'))
        return HttpResponseRedirect(auth_request.redirectURL(realm, return_to))
    error = request.GET.get('error', None)
    return render_to_response('login.html', {'error': error}, RequestContext(request))


def finish(request):
    auth_consumer = get_consumer(request)
    return_to = request.build_absolute_uri(reverse('openid_finish'))
    response = auth_consumer.complete(request.REQUEST, return_to)
    context = {
        consumer.CANCEL: {
            'error': 'OpenID authentication was cancelled.',
        },
        consumer.FAILURE: {
            'error': 'OpenID authentication failed.',
        },
        consumer.SUCCESS: {
            'identity': response.getDisplayIdentifier(),
        }
    }.get(response.status, {'error': 'Unknown response type.'})
    return render_to_response('finish.html', context, RequestContext(request))
