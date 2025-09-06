from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Configurar router para ViewSets
router = DefaultRouter()
router.register(r'auth', views.AuthViewSet, basename='auth')
router.register(r'users', views.UserViewSet, basename='users')

urlpatterns = [
    path('', include(router.urls)),
]