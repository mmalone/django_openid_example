from django.conf.urls.defaults import *

urlpatterns = patterns('',
    url(r'^$', 'oid.consumer.views.login', name='openid_login'),
    url(r'^finish/$', 'oid.consumer.views.finish', name='openid_finish'),
)
