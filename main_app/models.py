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

    malicious_url = models.URLField()
    http_response = models.PositiveSmallIntegerField()

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
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('CREATE', 'Create Incident'),
        ('UPDATE', 'Update Incident'),
        ('DELETE', 'Delete Incident'),
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

    def __str__(self):
        return f"{self.action} - {self.status}"
