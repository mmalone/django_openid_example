from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^consumer/', include('oid.consumer.urls')),
)
