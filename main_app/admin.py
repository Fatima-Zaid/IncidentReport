from django.contrib import admin
from .models import Incident, AuditLog


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "malicious_url",
        "severity",
        "created_by",
        "is_active",
        "created_at",
    )

    list_filter = (
        "severity",
        "is_active",
        "created_at",
    )

    search_fields = (
        "malicious_url",
        "description",
        "created_by__username",
    )

    readonly_fields = (
        "created_at",
        "updated_at",
    )

    ordering = ("-created_at",)

    actions = ["deactivate_incidents"]

    @admin.action(description="Deactivate selected incidents (soft delete)")
    def deactivate_incidents(self, request, queryset):
        queryset.update(is_active=False)


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

    list_filter = (
        "action",
        "status",
        "timestamp",
    )

    search_fields = (
        "user__username",
        "status",
        "details",
    )

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

    # 🔒 Disable add/delete for audit logs
    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False
