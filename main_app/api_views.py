from rest_framework import viewsets, status, generics
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404

from .models import Incident, AuditLog
from .serializers import (
    RegisterSerializer,
    UserSerializer,
    IncidentSerializer,
    IncidentCreateSerializer,
    IncidentUpdateSerializer,
    AuditLogSerializer
)
from .utils import create_audit_log, get_client_ip


# ============= AUTHENTICATION ENDPOINTS =============

@api_view(['POST'])
@permission_classes([AllowAny])
def register_api(request):
    """
    Register a new user
    POST /api/auth/register/
    Body: {
        "username": "string",
        "email": "string",
        "password": "string",
        "password2": "string"
    }
    """
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        
        # Create JWT tokens
        refresh = RefreshToken.for_user(user)
        
        # Create audit log
        create_audit_log(
            user,
            "LOGIN_SUCCESS",
            "success",
            request=request,
            details=f"User registered via API: {user.username}"
        )
        
        return Response({
            'message': 'User registered successfully',
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)
    
    # Log failed registration
    create_audit_log(
        None,
        "LOGIN_FAILED",
        "failed",
        request=request,
        details=f"Failed registration via API: {serializer.errors}"
    )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login_api(request):
    """
    Login user and get JWT tokens
    POST /api/auth/login/
    Body: {
        "username": "string",
        "password": "string"
    }
    """
    from django.contrib.auth import authenticate
    
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({
            'error': 'Please provide both username and password'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(username=username, password=password)
    
    if user is not None:
        # Create JWT tokens
        refresh = RefreshToken.for_user(user)
        
        # Create audit log
        create_audit_log(
            user,
            "LOGIN_SUCCESS",
            "success",
            request=request,
            details=f"User logged in via API: {user.username}"
        )
        
        return Response({
            'message': 'Login successful',
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_200_OK)
    else:
        # Log failed login
        create_audit_log(
            None,
            "LOGIN_FAILED",
            "failed",
            request=request,
            details=f"Failed login via API for username: {username}"
        )
        
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_api(request):
    """
    Logout user (blacklist refresh token)
    POST /api/auth/logout/
    Body: {
        "refresh": "refresh_token_string"
    }
    """
    try:
        refresh_token = request.data.get("refresh")
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        
        # Create audit log
        create_audit_log(
            request.user,
            "LOGOUT",
            "success",
            request=request,
            details=f"User logged out via API: {request.user.username}"
        )
        
        return Response({
            'message': 'Logout successful'
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


# ============= INCIDENT ENDPOINTS =============

class IncidentViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Incident CRUD operations
    
    Endpoints:
    - GET /api/incidents/ - List incidents (filtered by role)
    - POST /api/incidents/ - Create incident
    - GET /api/incidents/{id}/ - Get incident detail
    - PUT /api/incidents/{id}/ - Update incident (admin only)
    - PATCH /api/incidents/{id}/ - Partial update (admin only)
    - DELETE /api/incidents/{id}/ - Delete incident (admin only)
    """
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Filter incidents based on user role"""
        user = self.request.user
        if user.is_superuser:
            # Admin sees all incidents
            return Incident.objects.all()
        else:
            # Regular user sees only their own incidents
            return Incident.objects.filter(created_by=user)
    
    def get_serializer_class(self):
        """Use different serializers for different actions"""
        if self.action == 'create':
            return IncidentCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return IncidentUpdateSerializer
        return IncidentSerializer
    
    def list(self, request):
        """List incidents with optional filtering"""
        queryset = self.get_queryset()
        
        # Optional filters from query params
        severity = request.query_params.get('severity', None)
        if severity:
            queryset = queryset.filter(severity=severity)
        
        date_from = request.query_params.get('date_from', None)
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        
        date_to = request.query_params.get('date_to', None)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'count': queryset.count(),
            'results': serializer.data
        })
    
    def create(self, request):
        """Create a new incident"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Save with current user as creator
            incident = serializer.save(created_by=request.user)
            
            # Create audit log
            create_audit_log(
                request.user,
                "CREATE",
                "success",
                incident=incident,
                request=request,
                details=f"Created incident via API #{incident.id}: {incident.malicious_url}"
            )
            
            return Response(
                IncidentSerializer(incident).data,
                status=status.HTTP_201_CREATED
            )
        
        # Log failed creation
        create_audit_log(
            request.user,
            "CREATE",
            "failed",
            request=request,
            details=f"Failed to create incident via API: {serializer.errors}"
        )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def retrieve(self, request, pk=None):
        """Get incident by ID"""
        incident = get_object_or_404(Incident, pk=pk)
        
        # Check permission
        if not request.user.is_superuser and incident.created_by != request.user:
            create_audit_log(
                request.user,
                "VIEW",
                "failed",
                incident=incident,
                request=request,
                details=f"Unauthorized API access attempt to incident #{incident.id}"
            )
            return Response({
                'error': 'You do not have permission to view this incident'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Log successful view
        create_audit_log(
            request.user,
            "VIEW",
            "success",
            incident=incident,
            request=request,
            details=f"Viewed incident via API #{incident.id}"
        )
        
        serializer = IncidentSerializer(incident)
        return Response(serializer.data)
    
    def update(self, request, pk=None):
        """Update incident (admin only)"""
        incident = get_object_or_404(Incident, pk=pk)
        
        # Only admin can update
        if not request.user.is_superuser:
            create_audit_log(
                request.user,
                "UPDATE",
                "failed",
                incident=incident,
                request=request,
                details=f"Unauthorized API update attempt on incident #{incident.id}"
            )
            return Response({
                'error': 'Only administrators can update incidents'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(incident, data=request.data)
        if serializer.is_valid():
            updated_incident = serializer.save()
            
            create_audit_log(
                request.user,
                "UPDATE",
                "success",
                incident=updated_incident,
                request=request,
                details=f"Updated incident via API #{incident.id}"
            )
            
            return Response(IncidentSerializer(updated_incident).data)
        
        create_audit_log(
            request.user,
            "UPDATE",
            "failed",
            incident=incident,
            request=request,
            details=f"Failed to update incident via API #{incident.id}: {serializer.errors}"
        )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def partial_update(self, request, pk=None):
        """Partial update incident (admin only)"""
        incident = get_object_or_404(Incident, pk=pk)
        
        if not request.user.is_superuser:
            return Response({
                'error': 'Only administrators can update incidents'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(incident, data=request.data, partial=True)
        if serializer.is_valid():
            updated_incident = serializer.save()
            
            create_audit_log(
                request.user,
                "UPDATE",
                "success",
                incident=updated_incident,
                request=request,
                details=f"Partially updated incident via API #{incident.id}"
            )
            
            return Response(IncidentSerializer(updated_incident).data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, pk=None):
        """Delete incident (admin only)"""
        incident = get_object_or_404(Incident, pk=pk)
        
        # Only admin can delete
        if not request.user.is_superuser:
            create_audit_log(
                request.user,
                "DELETE",
                "failed",
                incident=incident,
                request=request,
                details=f"Unauthorized API delete attempt on incident #{incident.id}"
            )
            return Response({
                'error': 'Only administrators can delete incidents'
            }, status=status.HTTP_403_FORBIDDEN)
        
        incident_id = incident.id
        incident_url = incident.malicious_url
        
        create_audit_log(
            request.user,
            "DELETE",
            "success",
            incident=incident,
            request=request,
            details=f"Deleted incident via API #{incident_id}: {incident_url}"
        )
        
        incident.delete()
        
        return Response({
            'message': f'Incident #{incident_id} deleted successfully'
        }, status=status.HTTP_204_NO_CONTENT)


# ============= AUDIT LOG ENDPOINTS (ADMIN ONLY) =============

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for Audit Logs (Admin only, read-only)
    
    Endpoints:
    - GET /api/audit-logs/ - List all audit logs
    - GET /api/audit-logs/{id}/ - Get audit log detail
    """
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def list(self, request):
        """List audit logs with optional filtering"""
        queryset = self.get_queryset()
        
        # Optional filters
        action = request.query_params.get('action', None)
        if action:
            queryset = queryset.filter(action=action)
        
        status_filter = request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        user_id = request.query_params.get('user_id', None)
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'count': queryset.count(),
            'results': serializer.data
        })


# ============= CURRENT USER ENDPOINT =============

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user_api(request):
    """
    Get current authenticated user info
    GET /api/auth/me/
    """
    serializer = UserSerializer(request.user)
    return Response(serializer.data)
