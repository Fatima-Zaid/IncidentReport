from django.contrib import admin
from .models import Incident, AuditLog


# Register your models here.

@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "malicious_url_short",
        "severity",
        "created_by",
        "is_active",
        "created_at",
    )
    list_filter = ("severity", "is_active", "created_at", "created_by")
    search_fields = ("malicious_url", "description", "created_by__username")
    readonly_fields = ("created_at", "updated_at")
    ordering = ("-created_at",)

    fieldsets = (
        (
            "Incident Information",
            {
                "fields": (
                    "malicious_url",
                    "http_response",
                    "description",
                    "severity",
                    "screenshot",
                )
            },
        ),
        (
            "Metadata",
            {"fields": ("created_by", "is_active", "created_at", "updated_at")},
        ),
    )

    def malicious_url_short(self, obj):
        """Display shortened URL in admin list"""
        if len(obj.malicious_url) > 50:
            return obj.malicious_url[:50] + "..."
        return obj.malicious_url

    malicious_url_short.short_description = "Malicious URL"

    def get_queryset(self, request):
        """Optimize queryset with select_related"""
        qs = super().get_queryset(request)
        return qs.select_related("created_by")


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "action",
        "status",
        "incident",
        "ip_address",
        "timestamp",
    )
    list_filter = ("action", "status", "timestamp")
    search_fields = ("user__username", "details", "ip_address")
    readonly_fields = (
        "user",
        "incident",
        "action",
        "status",
        "ip_address",
        "timestamp",
        "details",
    )
    ordering = ("-timestamp",)

    fieldsets = (
        ("Log Information", {"fields": ("user", "action", "status", "incident")}),
        ("Additional Details", {"fields": ("ip_address", "timestamp", "details")}),
    )

    def has_add_permission(self, request):
        """Prevent manual creation of audit logs"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of audit logs"""
        return False

    def get_queryset(self, request):
        """Optimize queryset with select_related"""
        qs = super().get_queryset(request)
        return qs.select_related("user", "incident")
