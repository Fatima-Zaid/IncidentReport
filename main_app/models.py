from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


def validate_url_protocol(value):
    """Ensure URL starts with http or https"""
    if not value.startswith(('http://', 'https://')):
        raise ValidationError('URL must start with http:// or https://')


def validate_severity(value):
    """Ensure severity is in allowed range"""
    valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    if value not in valid_severities:
        raise ValidationError(f'Severity must be one of: {", ".join(valid_severities)}')


class Incident(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    malicious_url = models.URLField(
        max_length=500,
        validators=[validate_url_protocol]
    )
    http_response = models.TextField()

    description = models.TextField()

    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='LOW',
        validators=[validate_severity]
    )

    screenshot = models.ImageField(
        upload_to='incident_screenshots/',
        null=True,
        blank=True
    )

    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='incidents'
    )

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        """Model-level validation"""
        super().clean()

        # Validate URL
        if self.malicious_url and len(self.malicious_url) > 500:
            raise ValidationError({'malicious_url': 'URL is too long. Maximum 500 characters.'})

        # Validate description
        if self.description and len(self.description) < 10:
            raise ValidationError({'description': 'Description must be at least 10 characters long.'})

        # Validate HTTP response
        if not self.http_response or not self.http_response.strip():
            raise ValidationError({'http_response': 'HTTP Response is required.'})

    def save(self, *args, **kwargs):
        """Override save to call clean"""
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Incident {self.id} - {self.severity}"

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['created_at']),
        ]


class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('LOGIN_SUCCESS', 'Login Success'),
        ('LOGIN_FAILED', 'Login Failed'),
        ('LOGOUT', 'Logout'),
        ('CREATE', 'Create Incident'),
        ('UPDATE', 'Update Incident'),
        ('DELETE', 'Delete Incident'),
        ('VIEW', 'View Incident'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )

    incident = models.ForeignKey(
        Incident,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )

    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    status = models.CharField(max_length=20)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user} - {self.action} - {self.status} at {self.timestamp}"

