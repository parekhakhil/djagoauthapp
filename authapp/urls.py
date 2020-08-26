from django.urls import path
from .views import Registration
app_name = 'authapp'

urlpatterns = [
    path('register/',Registration.as_view(),name='register'),
]