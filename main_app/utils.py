from .models import AuditLog


def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def create_audit_log(user, action, status, incident=None, request=None, details=None):
    """
    Create an audit log entry

    Args:
        user: User object (can be None for failed login attempts)
        action: Action performed (from AuditLog.ACTION_CHOICES)
        status: Status of the action (success/failed)
        incident: Related incident object (optional)
        request: Django request object (optional, for IP extraction)
        details: Additional details text (optional)
    """
    ip_address = None
    if request:
        ip_address = get_client_ip(request)

    AuditLog.objects.create(
        user=user,
        incident=incident,
        action=action,
        status=status,
        ip_address=ip_address,
        details=details
    )
