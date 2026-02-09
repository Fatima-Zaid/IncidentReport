from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic import ListView, DetailView
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import PermissionDenied

from .forms import RegisterForm, IncidentForm, IncidentUpdateForm
from .models import Incident, AuditLog
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm


# Create your views here.
def home(request):
    return render(request, "home.html")


def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            # Ensure the user is NOT a superuser or staff
            user.is_superuser = False
            user.is_staff = False
            user.save()
            login(request, user)
            return redirect("home")
    else:
        form = RegisterForm()

    return render(request, "registration/register.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            return redirect("home")
    else:
        form = AuthenticationForm()

    return render(request, "registration/login.html", {"form": form})


@login_required
def logout_view(request):
    if request.method == "POST":
        logout(request)
        return redirect("home")
    return redirect("home")


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def create_audit_log(user, action, status, incident=None, request=None, details=None):
    ip_address = get_client_ip(request) if request else None
    AuditLog.objects.create(
        user=user,
        incident=incident,
        action=action,
        status=status,
        ip_address=ip_address,
        details=details,
    )


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
        raise PermissionDenied("You don't have permission to view this incident.")

    create_audit_log(
        request.user, "VIEW", "success", incident=incident, request=request
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
                request.user, "CREATE", "success", incident=incident, request=request
            )
            messages.success(request, "Incident created successfully!")
            return redirect("incident_detail", pk=incident.pk)
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
        raise PermissionDenied("Only administrators can edit incidents.")

    if request.method == "POST":
        form = IncidentUpdateForm(request.POST, request.FILES, instance=incident)
        if form.is_valid():
            form.save()
            create_audit_log(
                request.user, "UPDATE", "success", incident=incident, request=request
            )
            messages.success(request, "Incident updated successfully!")
            return redirect("incident_detail", pk=incident.pk)
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
        raise PermissionDenied("Only administrators can delete incidents.")

    if request.method == "POST":
        create_audit_log(
            request.user,
            "DELETE",
            "success",
            incident=incident,
            request=request,
            details=f"Deleted incident: {incident.malicious_url}",
        )
        incident.delete()
        messages.success(request, "Incident deleted successfully!")
        return redirect("incident_list")

    return render(
        request, "incidents/incident_confirm_delete.html", {"incident": incident}
    )
