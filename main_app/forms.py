from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import Incident


class RegisterForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ["username", "email"]

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get("password1") != cleaned_data.get("password2"):
            raise forms.ValidationError("Passwords do not match")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = [
            "malicious_url",
            "http_response",
            "description",
            "severity",
            "screenshot",
        ]
        widgets = {
            "malicious_url": forms.URLInput(attrs={"class": "validate"}),
            "http_response": forms.Textarea(
                attrs={"class": "materialize-textarea", "rows": 4}
            ),
            "description": forms.Textarea(
                attrs={"class": "materialize-textarea", "rows": 6}
            ),
            "severity": forms.Select(attrs={"class": "browser-default"}),
        }
        labels = {
            "malicious_url": "Malicious URL",
            "http_response": "HTTP Response",
            "description": "Incident Description",
            "severity": "Severity Level",
            "screenshot": "Screenshot (Optional)",
        }


class IncidentUpdateForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = [
            "malicious_url",
            "http_response",
            "description",
            "severity",
            "screenshot",
            "is_active",
        ]
        widgets = {
            "malicious_url": forms.URLInput(attrs={"class": "validate"}),
            "http_response": forms.Textarea(
                attrs={"class": "materialize-textarea", "rows": 4}
            ),
            "description": forms.Textarea(
                attrs={"class": "materialize-textarea", "rows": 6}
            ),
            "severity": forms.Select(attrs={"class": "browser-default"}),
        }
        labels = {
            "malicious_url": "Malicious URL",
            "http_response": "HTTP Response",
            "description": "Incident Description",
            "severity": "Severity Level",
            "screenshot": "Screenshot (Optional)",
            "is_active": "Active Status",
        }
