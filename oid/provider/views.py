import cgi
import random
from oid.store.models import DjangoOpenIDStore
from openid.server.server import Server, ProtocolError, EncodingError
from django.core.urlresolvers import reverse
from openid.yadis.constants import YADIS_CONTENT_TYPE
from openid.consumer.discover import OPENID_IDP_2_0_TYPE
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.http import HttpResponse


def get_server(request):
    return Server(DjangoOpenIDStore(), request.build_absolute_uri(reverse('openid_provider')))


def render_openid_response(openid_response):
    response = HttpResponse(openid_response.body, status=openid_response.code)
    for header, value in openid_response.headers.iteritems():
        response[header] = value
    return response


def xrds(request):
    return render_to_response('provider/xrds.xml', {
        'type_uri': OPENID_IDP_2_0_TYPE,
        'endpoint_url': request.build_absolute_uri(reverse('openid_provider')),
    }, RequestContext(request), mimetype=YADIS_CONTENT_TYPE)


def index(request):
    response = render_to_response('provider/index.html', {}, RequestContext(request))
    xrds_url = request.build_absolute_uri(reverse('xrds'))
    response['X-XRDS-Location'] = xrds_url
    return response


def openid_provider(request, identity=None):
    server = get_server(request)
    try:
        openid_request = server.decodeRequest(request.REQUEST)
    except ProtocolError, ex:
        return render_to_response('provider/index.html', {
            'error': str(ex),
        }, RequestContext(request))
    if openid_request is None:
        # No request, just render the template.
        return render_to_response('provider/index.html', {}, RequestContext(request))

    if openid_request.mode in ('checkid_immediate', 'checkid_setup'):
        # Got a checkid request. Always return yes. In a real server
        # we'd check that the user is logged in and ask them if they
        # trust the relying party, etc.
        if openid_request.idSelect():
            # If an identity URL wasn't entered at the RP, then we have to
            # come up with one. We'll ask the user who they want to be.
            if 'identity' in request.POST:
                identity = reverse('openid_identity', kwargs={'identity': request.POST['identity']})
                response = openid_request.answer(True, identity=request.build_absolute_uri(identity))
            else:
                return render_to_response('provider/index.html', {
                    'trust_root': openid_request.trust_root,
                    'needs_identity': True,
                }, RequestContext(request))
        else:
            response = openid_request.answer(True, identity=openid_request.identity)
    else:
        # Got some other kind of request. Let the server take care of it.
        response = server.handleRequest(openid_request)
    try:
        return render_openid_response(server.encodeResponse(response))
    except EncodingError, ex:
        return render_to_response('provider/index.html', {
            'error': cgi.escape(ex.response.encodeToKVForm()),
        }, RequestContext(request))


def openid_identity(request, identity):
    return render_to_response('provider/identity.html', {
        'provider': request.build_absolute_uri(reverse('openid_provider')),
        'identity': identity,
    }, RequestContext(request))
