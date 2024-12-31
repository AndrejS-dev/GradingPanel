from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("register", views.register, name="register"),
    path("login", views.login, name="login"),
    path("dashboard/<str:uid>", views.dashboard, name="dashboard"),
    path('verify-totp/', views.verify_totp, name='verify_totp'),
    ]