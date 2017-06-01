from django.conf.urls import url
from ping.views import status

urlpatterns = [
    url(r'^$', status, name='status'),
]
