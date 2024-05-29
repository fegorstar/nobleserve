from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from accounts.views import home

schema_view = get_schema_view(
    openapi.Info(
        title="Nobleserve Finance API Documentation",
        default_version='v1',
        description="Nobleserve Finance Company is a CBN licensed and regulated financial company with core focus on financial services.",
        terms_of_service="https://www.ourapp.com/policies/terms/",
        contact=openapi.Contact(email="cx@nobleservefinance.com"),
        license=openapi.License(name="Test License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path('auth/', include("accounts.urls")),
    path('', home, name='home'),
    path('customers/', include("customers.urls")),
    path('staffs/', include("staffs.urls")),
    path('administrator/', include("administrator.urls")),
    path('api/docs/', schema_view.with_ui('swagger',
         cache_timeout=0), name='schema-swagger-ui'),
    path('api/api.json/', schema_view.without_ui(cache_timeout=0),
         name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',
         cache_timeout=0), name='schema-redoc'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
