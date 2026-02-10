from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import api_views

# Create router for viewsets
router = DefaultRouter()
router.register(r'incidents', api_views.IncidentViewSet, basename='incident')
router.register(r'audit-logs', api_views.AuditLogViewSet, basename='auditlog')

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', api_views.register_api, name='api_register'),
    path('auth/login/', api_views.login_api, name='api_login'),
    path('auth/logout/', api_views.logout_api, name='api_logout'),
    path('auth/me/', api_views.current_user_api, name='api_current_user'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Include router URLs (incidents and audit-logs)
    path('', include(router.urls)),
]
