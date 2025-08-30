from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

# Opción 1: Con ViewSets (recomendado)
router = DefaultRouter()
# router.register(r'', views.DiagramViewSet)  # Descomenta cuando tengas el ViewSet
urlpatterns = router.urls