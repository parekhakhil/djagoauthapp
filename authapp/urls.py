from django.urls import path
from .views import RegistrationView,LoginView
app_name = 'authapp'

urlpatterns = [
    path('register/',RegistrationView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
]