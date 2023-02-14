from site import venv
from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('signup', views.signup, name='signup'),
    path('signin', views.signin, name='signin'),
    path('home', views.home, name='home'),
    path('signout', views.signout, name='singout'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('email_confirm', views.email_confirm, name='email_confirm'),
    path('reset_password', views.reset_pass, name='reset_password'),
    path('reset/<uidb64>/<token>', views.reset, name='reset'),
    path('update_password', views.update_password, name='update_password'),
    
]