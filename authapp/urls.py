from django.urls import path
from .views import (RegistrationView,
                                    RequestResetEmailView,
                                        LogoutView,
                                        HomeView,
                                        LoginView,
                                        ActivateAccountView,
                                        ResetPasswordView)
#from .views import change_password
from django.contrib.auth.decorators import login_required
app_name = 'authapp'

urlpatterns = [
    path('register/',RegistrationView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('activate/<uidb64>/<token>',ActivateAccountView.as_view(),name='activate'),
    path('', login_required(HomeView.as_view()), name='home'),
    path('logout/',LogoutView.as_view(), name='logout'),
    path('request-reset-email/',RequestResetEmailView.as_view(),name='request-reset-email'),
    path('reset-password/<uidb64>/<token>',ResetPasswordView.as_view(),name='reset-password'),
  # path(
   #     'change-password/',login_required(change_password),
    #    name='change_password'
   # ),
]