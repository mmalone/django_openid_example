from django.conf.urls.defaults import *

urlpatterns = patterns('',
    url(r'^xrds/$', 'oid.provider.views.xrds', name='xrds'),
    url(r'^$', 'oid.provider.views.openid_provider', name='openid_provider'),
    url(r'^identity/(?P<identity>[a-zA-Z0-9]+)/$', 'oid.provider.views.openid_identity', name='openid_identity'),
)
