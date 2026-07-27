"""HTTP routes for the Anva API and server-rendered application."""

from __future__ import annotations

from django.urls import path

from anva.foundation import views

urlpatterns = [
    path("", views.home, name="home"),
    path("health/live", views.liveness, name="liveness"),
    path("health/ready", views.readiness, name="readiness"),
]
