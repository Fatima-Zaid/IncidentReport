from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Incident, AuditLog
import bleach
import re


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_superuser']
        read_only_fields = ['id', 'is_superuser']


class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']

    def validate_username(self, value):
        """Validate username - only alphanumeric and underscores"""
        if not re.match(r'^[\w]+$', value):
            raise serializers.ValidationError(
                'Username can only contain letters, numbers, and underscores.'
            )
        return value

    def validate_email(self, value):
        """Validate email uniqueness"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('This email is already registered.')
        return value

    def validate(self, data):
        """Validate that passwords match"""
        if data['password'] != data['password2']:
            raise serializers.ValidationError({
                "password2": "Passwords do not match."
            })
        return data

    def create(self, validated_data):
        """Create new user"""
        validated_data.pop('password2')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        user.is_superuser = False
        user.is_staff = False
        user.save()
        return user


class IncidentSerializer(serializers.ModelSerializer):
    """Serializer for Incident model"""
    created_by = UserSerializer(read_only=True)
    created_by_id = serializers.IntegerField(read_only=True, source='created_by.id')

    class Meta:
        model = Incident
        fields = [
            'id',
            'malicious_url',
            'http_response',
            'description',
            'severity',
            'screenshot',
            'created_by',
            'created_by_id',
            'is_active',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_by', 'created_by_id', 'created_at', 'updated_at']

    def validate_malicious_url(self, value):
        """Validate and sanitize URL"""
        if not value:
            raise serializers.ValidationError('URL is required.')

        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError('URL must start with http:// or https://')

        # Sanitize URL
        value = bleach.clean(value, tags=[], strip=True)

        if len(value) > 500:
            raise serializers.ValidationError('URL is too long. Maximum 500 characters.')

        return value

    def validate_http_response(self, value):
        """Validate and sanitize HTTP response"""
        if not value or value.strip() == '':
            raise serializers.ValidationError('HTTP Response is required.')

        # Sanitize HTML/script tags
        allowed_tags = ['p', 'br', 'strong', 'em', 'code', 'pre']
        value = bleach.clean(value, tags=allowed_tags, strip=True)

        if len(value) > 10000:
            raise serializers.ValidationError(
                'HTTP Response is too long. Maximum 10,000 characters.'
            )

        return value

    def validate_description(self, value):
        """Validate and sanitize description"""
        if not value or value.strip() == '':
            raise serializers.ValidationError('Description is required.')

        # Sanitize - remove all HTML tags
        value = bleach.clean(value, tags=[], strip=True)

        if len(value) < 10:
            raise serializers.ValidationError(
                'Description must be at least 10 characters long.'
            )

        if len(value) > 5000:
            raise serializers.ValidationError(
                'Description is too long. Maximum 5,000 characters.'
            )

        return value

    def validate_severity(self, value):
        """Validate severity"""
        valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        if value not in valid_severities:
            raise serializers.ValidationError('Invalid severity level selected.')
        return value

    def validate_screenshot(self, value):
        """Validate screenshot file"""
        if value:
            # Validate file size (max 5MB)
            if value.size > 5 * 1024 * 1024:
                raise serializers.ValidationError(
                    'Screenshot file size cannot exceed 5MB.'
                )

            # Validate file type
            valid_extensions = ['jpg', 'jpeg', 'png', 'gif']
            ext = value.name.split('.')[-1].lower()
            if ext not in valid_extensions:
                raise serializers.ValidationError(
                    'Only JPG, JPEG, PNG, and GIF files are allowed.'
                )

        return value


class IncidentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating incidents (users)"""
    class Meta:
        model = Incident
        fields = [
            'malicious_url',
            'http_response',
            'description',
            'severity',
            'screenshot'
        ]

    # Reuse validation methods
    validate_malicious_url = IncidentSerializer.validate_malicious_url
    validate_http_response = IncidentSerializer.validate_http_response
    validate_description = IncidentSerializer.validate_description
    validate_severity = IncidentSerializer.validate_severity
    validate_screenshot = IncidentSerializer.validate_screenshot


class IncidentUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating incidents (admin only)"""
    class Meta:
        model = Incident
        fields = [
            'malicious_url',
            'http_response',
            'description',
            'severity',
            'screenshot',
            'is_active'
        ]

    # Reuse validation methods
    validate_malicious_url = IncidentSerializer.validate_malicious_url
    validate_http_response = IncidentSerializer.validate_http_response
    validate_description = IncidentSerializer.validate_description
    validate_severity = IncidentSerializer.validate_severity
    validate_screenshot = IncidentSerializer.validate_screenshot


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for Audit Log model"""
    user = UserSerializer(read_only=True)
    incident_id = serializers.IntegerField(source='incident.id', read_only=True, allow_null=True)

    class Meta:
        model = AuditLog
        fields = [
            'id',
            'user',
            'incident_id',
            'action',
            'status',
            'ip_address',
            'timestamp',
            'details'
        ]
        read_only_fields = ['id', 'user', 'incident_id', 'timestamp']
