from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Incident(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    malicious_url = models.URLField(max_length=500)  # Added max_length for long URLs
    http_response = models.TextField()  # Changed to TextField to store full HTTP response content

    description = models.TextField()

    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='LOW'
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
    updated_at = models.DateTimeField(auto_now=True)  # Added to track updates

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
        blank=True
    )

    incident = models.ForeignKey(
        Incident,
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    action = models.CharField(
        max_length=20,
        choices=ACTION_CHOICES
    )

    status = models.CharField(max_length=20)

    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    timestamp = models.DateTimeField(auto_now_add=True)

    details = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.user} - {self.action} - {self.status} at {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
