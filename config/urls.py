from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from incidents.auth_views import RateLimitedLoginView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/login/", RateLimitedLoginView.as_view(), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("incidents.urls")),
]
admin.site.site_header = "Incident Desk administration"
admin.site.site_title = "Incident Desk"
