from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^consumer/', include('oid.consumer.urls')),
    (r'^op/', include('oid.provider.urls')),
    (r'^$', 'oid.provider.views.index'),
)
