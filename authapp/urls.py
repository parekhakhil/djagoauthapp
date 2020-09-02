from django.urls import path
from .views import RegistrationView,LogoutView,HomeView,LoginView,ActivateAccountView
from django.contrib.auth.decorators import login_required
app_name = 'authapp'

urlpatterns = [
    path('register/',RegistrationView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('activate/<uidb64>/<token>',ActivateAccountView.as_view(),name='activate'),
    path('', login_required(HomeView.as_view()), name='home'),
    path('logout/',LogoutView.as_view(), name='logout'),
]