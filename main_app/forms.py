from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Incident
from django.core.exceptions import ValidationError
import bleach
import re


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

    def clean_username(self):
        username = self.cleaned_data.get('username')
        # Sanitize username - only allow alphanumeric and underscores
        if not re.match(r'^[\w]+$', username):
            raise ValidationError('Username can only contain letters, numbers, and underscores.')
        return username

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError('This email is already registered.')
        return email


class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['malicious_url', 'http_response', 'description', 'severity', 'screenshot']
        widgets = {
            'malicious_url': forms.URLInput(attrs={'class': 'validate'}),
            'http_response': forms.Textarea(attrs={'class': 'materialize-textarea', 'rows': 4}),
            'description': forms.Textarea(attrs={'class': 'materialize-textarea', 'rows': 6}),
            'severity': forms.Select(attrs={'class': 'browser-default'}),
        }
        labels = {
            'malicious_url': 'Malicious URL',
            'http_response': 'HTTP Response',
            'description': 'Incident Description',
            'severity': 'Severity Level',
            'screenshot': 'Screenshot (Optional)',
        }

    def clean_malicious_url(self):
        url = self.cleaned_data.get('malicious_url')

        # Validate that URL is not empty
        if not url:
            raise ValidationError('URL is required.')

        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            raise ValidationError('URL must start with http:// or https://')

        # Sanitize URL - remove dangerous characters
        url = bleach.clean(url, tags=[], strip=True)

        # Check URL length
        if len(url) > 500:
            raise ValidationError('URL is too long. Maximum 500 characters.')

        return url

    def clean_http_response(self):
        http_response = self.cleaned_data.get('http_response')

        # Validate that HTTP response is not empty
        if not http_response or http_response.strip() == '':
            raise ValidationError('HTTP Response is required.')

        # Sanitize HTML/script tags from HTTP response
        # Allow some safe tags but remove dangerous ones
        allowed_tags = ['p', 'br', 'strong', 'em', 'code', 'pre']
        http_response = bleach.clean(
            http_response,
            tags=allowed_tags,
            strip=True
        )

        # Check length
        if len(http_response) > 10000:
            raise ValidationError('HTTP Response is too long. Maximum 10,000 characters.')

        return http_response

    def clean_description(self):
        description = self.cleaned_data.get('description')

        # Validate that description is not empty
        if not description or description.strip() == '':
            raise ValidationError('Description is required.')

        # Sanitize description - remove all HTML tags
        description = bleach.clean(description, tags=[], strip=True)

        # Check minimum length
        if len(description) < 10:
            raise ValidationError('Description must be at least 10 characters long.')

        # Check maximum length
        if len(description) > 5000:
            raise ValidationError('Description is too long. Maximum 5,000 characters.')

        return description

    def clean_severity(self):
        severity = self.cleaned_data.get('severity')

        # Validate severity is in allowed choices
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if severity not in valid_severities:
            raise ValidationError('Invalid severity level selected.')

        return severity

    def clean_screenshot(self):
        screenshot = self.cleaned_data.get('screenshot')

        if screenshot:
            # Validate file size (max 5MB)
            if screenshot.size > 5 * 1024 * 1024:
                raise ValidationError('Screenshot file size cannot exceed 5MB.')

            # Validate file type
            valid_extensions = ['jpg', 'jpeg', 'png', 'gif']
            ext = screenshot.name.split('.')[-1].lower()
            if ext not in valid_extensions:
                raise ValidationError('Only JPG, JPEG, PNG, and GIF files are allowed.')

        return screenshot


class IncidentUpdateForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = ['malicious_url', 'http_response', 'description', 'severity', 'screenshot', 'is_active']
        widgets = {
            'malicious_url': forms.URLInput(attrs={'class': 'validate'}),
            'http_response': forms.Textarea(attrs={'class': 'materialize-textarea', 'rows': 4}),
            'description': forms.Textarea(attrs={'class': 'materialize-textarea', 'rows': 6}),
            'severity': forms.Select(attrs={'class': 'browser-default'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'filled-in'}),  # checkbox for admin
        }
        labels = {
            'malicious_url': 'Malicious URL',
            'http_response': 'HTTP Response',
            'description': 'Incident Description',
            'severity': 'Severity Level',
            'screenshot': 'Screenshot (Optional)',
            'is_active': 'Active Status',
        }

    # Keep all clean methods from IncidentForm
    def clean_malicious_url(self):
        url = self.cleaned_data.get('malicious_url')
        if not url:
            raise ValidationError('URL is required.')
        if not url.startswith(('http://', 'https://')):
            raise ValidationError('URL must start with http:// or https://')
        import bleach
        url = bleach.clean(url, tags=[], strip=True)
        if len(url) > 500:
            raise ValidationError('URL is too long. Maximum 500 characters.')
        return url

    def clean_http_response(self):
        http_response = self.cleaned_data.get('http_response')
        if not http_response or http_response.strip() == '':
            raise ValidationError('HTTP Response is required.')
        allowed_tags = ['p', 'br', 'strong', 'em', 'code', 'pre']
        import bleach
        http_response = bleach.clean(http_response, tags=allowed_tags, strip=True)
        if len(http_response) > 10000:
            raise ValidationError('HTTP Response is too long. Maximum 10,000 characters.')
        return http_response

    def clean_description(self):
        description = self.cleaned_data.get('description')
        if not description or description.strip() == '':
            raise ValidationError('Description is required.')
        import bleach
        description = bleach.clean(description, tags=[], strip=True)
        if len(description) < 10:
            raise ValidationError('Description must be at least 10 characters long.')
        if len(description) > 5000:
            raise ValidationError('Description is too long. Maximum 5,000 characters.')
        return description

    def clean_severity(self):
        severity = self.cleaned_data.get('severity')
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if severity not in valid_severities:
            raise ValidationError('Invalid severity level selected.')
        return severity

    def clean_screenshot(self):
        screenshot = self.cleaned_data.get('screenshot')
        if screenshot and hasattr(screenshot, 'size'):
            if screenshot.size > 5 * 1024 * 1024:
                raise ValidationError('Screenshot file size cannot exceed 5MB.')
            valid_extensions = ['jpg', 'jpeg', 'png', 'gif']
            ext = screenshot.name.split('.')[-1].lower()
            if ext not in valid_extensions:
                raise ValidationError('Only JPG, JPEG, PNG, and GIF files are allowed.')
        return screenshot
