from django.urls import include, path
from .views import search
urlpatterns = [
    path("training/search/", search, name="training-search"),
    path("", include("config.urls")),
]
