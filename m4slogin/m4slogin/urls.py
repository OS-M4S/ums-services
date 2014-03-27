from django.conf.urls import patterns, include, url

from tastypie.api import Api
from users.resources import *

from django.contrib import admin
admin.autodiscover()

api_v1 = Api(api_name='v1')
api_v1.register(UserProfileResource())
api_v1.register(UserResource())
api_v1.register(CreateUserResource())

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'm4slogin.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^api/', include(api_v1.urls)),
)
