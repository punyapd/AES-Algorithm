from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("about/", views.about, name="about"),
    path("encrypt_decrypt/", views.encrypt_decrypt, name="encrypt_decrypt"),
    path("encrypt/", views.encrypt_view, name="encrypt"),
    path("decrypt/", views.decrypt_view, name="decrypt"),
]
