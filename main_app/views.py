from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic import ListView, DetailView
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.core.paginator import Paginator

from .forms import RegisterForm, IncidentForm, IncidentUpdateForm
from .models import Incident, AuditLog
from .utils import create_audit_log
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm


# Helper function to check if user is superuser
def is_superuser(user):
    return user.is_superuser


# Home view
def home(request):
    return render(request, "home.html")


# Registration view
def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_superuser = False
            user.is_staff = False
            user.save()
            login(request, user)
            create_audit_log(
                user,
                "LOGIN_SUCCESS",
                "success",
                request=request,
                details=f"User registered and logged in: {user.username}",
            )
            messages.success(
                request,
                "Registration successful! Welcome to Incident Reporting System.",
            )
            return redirect("home")
        else:
            create_audit_log(
                None,
                "LOGIN_FAILED",
                "failed",
                request=request,
                details=f"Failed registration attempt",
            )
    else:
        form = RegisterForm()
    return render(request, "registration/register.html", {"form": form})


# Login view
def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            create_audit_log(
                user,
                "LOGIN_SUCCESS",
                "success",
                request=request,
                details=f"User logged in: {user.username}",
            )
            messages.success(request, f"Welcome back, {user.username}!")
            return redirect("home")
        else:
            username = request.POST.get("username", "unknown")
            create_audit_log(
                None,
                "LOGIN_FAILED",
                "failed",
                request=request,
                details=f"Failed login attempt for username: {username}",
            )
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, "registration/login.html", {"form": form})


# Logout view
@login_required
def logout_view(request):
    if request.method == "POST":
        username = request.user.username
        create_audit_log(
            request.user,
            "LOGOUT",
            "success",
            request=request,
            details=f"User logged out: {username}",
        )
        logout(request)
        messages.success(request, "You have been logged out successfully.")
        return redirect("home")
    return redirect("home")


# ============= INCIDENT CRUD OPERATIONS =============


# List incidents (role-based)
@login_required
def incident_list(request):
    if request.user.is_superuser:
        # Admin sees all incidents
        incidents = Incident.objects.all()
    else:
        # Regular user sees only their own incidents
        incidents = Incident.objects.filter(created_by=request.user)

    return render(request, "incidents/incident_list.html", {"incidents": incidents})


# View incident detail
@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(Incident, pk=pk)

    # Check permission: user can only view their own incidents unless admin
    if not request.user.is_superuser and incident.created_by != request.user:
        create_audit_log(
            request.user,
            "VIEW",
            "failed",
            incident=incident,
            request=request,
            details=f"Unauthorized access attempt to incident #{incident.id}",
        )
        raise PermissionDenied("You don't have permission to view this incident.")

    create_audit_log(
        request.user,
        "VIEW",
        "success",
        incident=incident,
        request=request,
        details=f"Viewed incident #{incident.id}: {incident.malicious_url}",
    )

    return render(request, "incidents/incident_detail.html", {"incident": incident})


# Create incident (users only)
@login_required
def incident_create(request):
    if request.method == "POST":
        form = IncidentForm(request.POST, request.FILES)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.created_by = request.user
            incident.save()

            create_audit_log(
                request.user,
                "CREATE",
                "success",
                incident=incident,
                request=request,
                details=f"Created incident #{incident.id}: {incident.malicious_url} with severity {incident.severity}",
            )
            messages.success(request, "Incident created successfully!")
            return redirect("incident_detail", pk=incident.pk)
        else:
            create_audit_log(
                request.user,
                "CREATE",
                "failed",
                request=request,
                details=f"Failed to create incident - validation errors",
            )
            messages.error(request, "Please correct the errors below.")
    else:
        form = IncidentForm()

    return render(
        request, "incidents/incident_form.html", {"form": form, "action": "Create"}
    )


# Update incident (admin only)
@login_required
def incident_update(request, pk):
    incident = get_object_or_404(Incident, pk=pk)

    # Only admin can edit
    if not request.user.is_superuser:
        create_audit_log(
            request.user,
            "UPDATE",
            "failed",
            incident=incident,
            request=request,
            details=f"Unauthorized update attempt on incident #{incident.id}",
        )
        raise PermissionDenied("Only administrators can edit incidents.")

    if request.method == "POST":
        form = IncidentUpdateForm(request.POST, request.FILES, instance=incident)
        if form.is_valid():
            updated_incident = form.save()
            create_audit_log(
                request.user,
                "UPDATE",
                "success",
                incident=updated_incident,
                request=request,
                details=f"Updated incident #{incident.id}: Changed severity to {updated_incident.severity}, active status: {updated_incident.is_active}",
            )
            messages.success(request, "Incident updated successfully!")
            return redirect("incident_detail", pk=incident.pk)
        else:
            create_audit_log(
                request.user,
                "UPDATE",
                "failed",
                incident=incident,
                request=request,
                details=f"Failed to update incident #{incident.id} - validation errors",
            )
            messages.error(request, "Please correct the errors below.")
    else:
        form = IncidentUpdateForm(instance=incident)

    return render(
        request,
        "incidents/incident_form.html",
        {"form": form, "action": "Update", "incident": incident},
    )


# Delete incident (admin only)
@login_required
def incident_delete(request, pk):
    incident = get_object_or_404(Incident, pk=pk)

    # Only admin can delete
    if not request.user.is_superuser:
        create_audit_log(
            request.user,
            "DELETE",
            "failed",
            incident=incident,
            request=request,
            details=f"Unauthorized delete attempt on incident #{incident.id}",
        )
        raise PermissionDenied("Only administrators can delete incidents.")

    if request.method == "POST":
        incident_id = incident.id
        incident_url = incident.malicious_url
        create_audit_log(
            request.user,
            "DELETE",
            "success",
            incident=incident,
            request=request,
            details=f"Deleted incident #{incident_id}: {incident_url} (Severity: {incident.severity})",
        )
        incident.delete()
        messages.success(request, "Incident deleted successfully!")
        return redirect("incident_list")

    return render(
        request, "incidents/incident_confirm_delete.html", {"incident": incident}
    )


# ============= AUDIT LOG VIEWS (ADMIN ONLY) =============


@login_required
@user_passes_test(is_superuser, login_url="/")
def audit_log_list(request):
    """View all audit logs - Admin only"""

    # Get filter parameters
    action_filter = request.GET.get("action", "")
    status_filter = request.GET.get("status", "")
    user_filter = request.GET.get("user", "")
    search = request.GET.get("search", "")

    # Base queryset
    logs = AuditLog.objects.all().select_related("user", "incident")

    # Apply filters
    if action_filter:
        logs = logs.filter(action=action_filter)

    if status_filter:
        logs = logs.filter(status=status_filter)

    if user_filter:
        logs = logs.filter(user__username__icontains=user_filter)

    if search:
        logs = logs.filter(
            Q(details__icontains=search)
            | Q(user__username__icontains=search)
            | Q(ip_address__icontains=search)
        )

    # Pagination
    paginator = Paginator(logs, 50)  # Show 50 logs per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    # Get unique actions and statuses for filter dropdowns
    actions = AuditLog.ACTION_CHOICES
    statuses = AuditLog.objects.values_list("status", flat=True).distinct()

    context = {
        "page_obj": page_obj,
        "actions": actions,
        "statuses": statuses,
        "action_filter": action_filter,
        "status_filter": status_filter,
        "user_filter": user_filter,
        "search": search,
    }

    return render(request, "audit/audit_log_list.html", context)


@login_required
@user_passes_test(is_superuser, login_url="/")
def audit_log_detail(request, pk):
    """View detailed audit log - Admin only"""
    log = get_object_or_404(AuditLog, pk=pk)
    return render(request, "audit/audit_log_detail.html", {"log": log})
