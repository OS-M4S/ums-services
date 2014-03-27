from tastypie.resources import ModelResource
from users.models import UserProfile
#from .utils import MINIMUM_PASSWORD_LENGTH, validate_password
from .exceptions import CustomBadRequest
from tastypie.authentication import Authentication, MultiAuthentication
from tastypie.authentication import BasicAuthentication, ApiKeyAuthentication
from tastypie.authorization import Authorization

from django.conf.urls import url
from tastypie.utils import trailing_slash

from tastypie import fields
from django.contrib.auth.models import User

from django.contrib.auth.hashers import make_password


class CreateUserResource(ModelResource):
    user = fields.ForeignKey('users.resources.UserResource', 'user', full=True)

    class Meta:
        allowed_methods = ['post']
        always_return_data = True
        authentication = Authentication()
        authorization = Authorization()
        queryset = UserProfile.objects.all()
        resource_name = 'createuser'
        always_return_data = True

    def hydrate(self, bundle):
        print 'hydrate CreateUserResource'
        REQUIRED_USER_PROFILE_FIELDS = ( "gender", "user")
        for field in REQUIRED_USER_PROFILE_FIELDS:
            if field not in bundle.data:
                raise CustomBadRequest(
                    code="missing_key",
                    message="Must provide {missing_key} when creating a user."
                            .format(missing_key=field))

        REQUIRED_USER_FIELDS = ("username", "email", "first_name", "last_name",
                                "raw_password")
        for field in REQUIRED_USER_FIELDS:
            if field not in bundle.data["user"]:
                raise CustomBadRequest(
                    code="missing_key",
                    message="Must provide {missing_key} when creating a user."
                            .format(missing_key=field))
        return bundle

    def obj_create(self, bundle, **kwargs):
        try:
            # validate username
            username = bundle.data["user"]["username"]
            if User.objects.filter(username=username):
                raise CustomBadRequest(
                    code="duplicate_exception",
                    message="That username is already used.")
            # validate user email
            email = bundle.data["user"]["email"]
            if User.objects.filter(email=email):
                raise CustomBadRequest(
                    code="duplicate_exception",
                    message="That email is already used.")
            # validate password
            rp = bundle.data["user"]["raw_password"]
            if not self.validate_password(rp):
                if len(rp) < MINIMUM_PASSWORD_LENGTH:
                    raise CustomBadRequest(
                        code="invalid_password",
                        message=(
                            "Your password should contain at least {length} "
                            "characters.".format(length=
                                                 MINIMUM_PASSWORD_LENGTH)))
                raise CustomBadRequest(
                    code="invalid_password",
                    message=("Your password should contain at least one number"
                             ", one uppercase letter, one special character,"
                             " and no spaces."))
        except KeyError as missing_key:
            raise CustomBadRequest(
                code="missing_key",
                message="Must provide {missing_key} when creating a user."
                        .format(missing_key=missing_key))
        except User.DoesNotExist:
            print 'Error Error'
        # setting resource_name to `user_profile` here because we want
        # resource_uri in response to be same as UserProfileResource resource
        self._meta.resource_name = UserProfileResource._meta.resource_name
        return super(CreateUserResource, self).obj_create(bundle, **kwargs)

    def validate_password(self, password):
        if re.match(REGEX_VALID_PASSWORD, password):
            return True
        # Todo fix this
        return False

################################################################################
################################################################################


import re

MINIMUM_PASSWORD_LENGTH = 3
REGEX_VALID_PASSWORD = (
    ## Don't allow any spaces, e.g. '\t', '\n' or whitespace etc.
    r'^(?!.*[\s])'
    ## Check for a digit
    '((?=.*[\d])'
    ## Check for an uppercase letter
    '(?=.*[A-Z])'
    ## check for special characters. Something which is not word, digit or
    ## space will be treated as special character
    '(?=.*[^\w\d\s])).'
    ## Minimum number of characters
    '{' + str(MINIMUM_PASSWORD_LENGTH) + ',}$')


class UserResource(ModelResource):
    raw_password = fields.CharField(attribute=None, readonly=True, blank=True, null=True)

    class Meta:
        # authentication = MultiAuthentication(BasicAuthentication(), ApiKeyAuthentication())
        authentication = ApiKeyAuthentication()
        authorization = Authorization()
        allowed_methods = ['get', 'patch', 'put', ]
        always_return_data = True
        queryset = User.objects.all().select_related('api_key')
        excludes = ['is_active', 'is_staff', 'is_superuser', 'date_joined', 'last_login']
        resource_name = 'user'

    # def override_urls(self):
    #     return [
    #         # url(r"^(?P<resource_name>%s)/login%s$" %
    #         #     (self._meta.resource_name, trailing_slash()),
    #         #     self.wrap_view('login'), name="api_login"),
    #         url(r"^(?P<resource_name>%s)/login%s$" %
    #             (self._meta.resource_name, trailing_slash()),
    #             self.wrap_view('login'), name="api_login"),
    #         url(r'^(?P<resource_name>%s)/logout%s$' %
    #             (self._meta.resource_name, trailing_slash()),
    #             self.wrap_view('logout'), name='api_logout'),
    #     ]

    # def authorized_read_list(self, object_list, bundle):
    #     return object_list.filter(id=bundle.request.user.id).select_related()



    def hydrate(self, bundle):
        print 'hydrate UserResource'
        if "raw_password" in bundle.data:
            print 'raw_password in bundle.data > '
            # Pop out raw_password and validate it
            # This will prevent re-validation because hydrate is called
            # multiple times
            # https://github.com/toastdriven/django-tastypie/issues/603
            # "Cannot resolve keyword 'raw_password' into field." won't occur

            print bundle.data
            # print bundle.data['user']['raw_password']
            rp = bundle.data["raw_password"]
            del bundle.data['raw_password']

            # Validate password
            # if not self.validate_password(rp):
            #     # raise CustomBadRequest(code="invalid password", message="Password must be at least 8 characters with one digit, one uppercase letter and one special character")
            #     raise CustomBadRequest(code="invalid_password", message="invalid password")
            #     if len(rp) < MINIMUM_PASSWORD_LENGTH:
            #         raise CustomBadRequest(
            #             code="invalid_password",
            #             message=(
            #                 "Your password should contain at least {length} "
            #                 "characters.".format(length=
            #                                      MINIMUM_PASSWORD_LENGTH)))
            #     raise CustomBadRequest(
            #         code="invalid_password",
            #         message=("Your password should contain at least one number"
            #                  ", one uppercase letter, one special character,"
            #                  " and no spaces."))
            bundle.data["password"] = make_password(rp)
            print bundle.data
        return bundle

    def dehydrate(self, bundle):
        bundle.data['key'] = bundle.obj.api_key.key
        try:
            del bundle.data['raw_password']
            #remove bundle.data['password']
        except KeyError:
            print 'KeyError'
        return bundle

    def get_list(self, request, **kwargs):
        try:
            kwargs['pk'] = request.user.profile.pk
        except:
            print ' >> No profile for this user'
        return super(UserResource, self).get_detail(request, **kwargs)

    # def login(self, request, **kwargs):
    #     self.method_check(request, allowed=['post'])

    #     data = self.deserialize(request, request.raw_post_data, format=request.META.get('CONTENT_TYPE', 'application/json'))

    #     username = data.get('username', '')
    #     password = data.get('password', '')

    #     user = authenticate(username=username, password=password)
    #     if user:
    #         if user.is_active:
    #             login(request, user)
    #             return self.create_response(request, {
    #                 'success': True
    #             })
    #         else:
    #             return self.create_response(request, {
    #                 'success': False,
    #                 'reason': 'disabled',
    #                 }, HttpForbidden )
    #     else:
    #         return self.create_response(request, {
    #             'success': False,
    #             'reason': 'incorrect',
    #             }, HttpUnauthorized )

###############################################################################
###############################################################################


class UserProfileResource(ModelResource):
    class Meta:
        queryset = UserProfile.objects.all()
        # authentication = MultiAuthentication(BasicAuthentication(), ApiKeyAuthentication())
        authentication = ApiKeyAuthentication()
        authorization = Authorization()
        always_return_data = True
        allowed_methods = ['get', 'patch', ]
        detail_allowed_methods = ['get', 'patch', 'put']
        resource_name = 'userprofile'

    # def authorized_read_list(self, object_list, bundle):
    #     return object_list.filter(user=bundle.request.user).select_related()

    ## Since there is only one user profile object, call get_detail instead
    def get_list(self, request, **kwargs):
        try:
            kwargs["pk"] = request.user.profile.pk
        except:
            print 'User has no profile'
        return super(UserProfileResource, self).get_detail(request, **kwargs)


###############################################################################
###############################################################################
