from django.urls import path
from . import views

urlpatterns = [
    path('review-diagram/', views.ReviewDiagramView.as_view(), name='review-diagram'),
]