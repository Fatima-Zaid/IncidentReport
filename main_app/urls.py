from django.urls import path, include
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),


    path("incidents/", views.incident_list, name="incident_list"),
    path("incidents/create/", views.incident_create, name="incident_create"),
    path("incidents/<int:pk>/", views.incident_detail, name="incident_detail"),
    path("incidents/<int:pk>/update/", views.incident_update, name="incident_update"),
    path("incidents/<int:pk>/delete/", views.incident_delete, name="incident_delete"),
]
