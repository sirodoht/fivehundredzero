from django.urls import path
from main import views

urlpatterns = [
    path("postmark/", views.postmark_webhook, name="postmark_webhook"),
    path("health/", views.health, name="health"),
]
