import secrets
from datetime import datetime

from django.contrib.auth.models import AbstractUser, PermissionsMixin
from django.db import models
from django_extensions.db.models import TimeStampedModel
from phone_field import PhoneField
from rest_framework_simplejwt.tokens import RefreshToken

from .managers import CustomUserManager


class BaseUser(AbstractUser, PermissionsMixin):
    class RoleChoice(models.TextChoices):
        ADMIN = 'Admin', 'Admin'
        MANAGER = 'Manager', 'Manager'
        EMPLOYEE = 'Employee', 'Employee'

    email = models.EmailField(unique=True, db_index=True, null=False)
    password = models.CharField(max_length=100)
    username = models.CharField(max_length=50, unique=False, null=True)
    phone_number = PhoneField(blank=True, help_text='Contact phone number')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    role = models.CharField(choices=RoleChoice, blank=True, null=True, default=RoleChoice.EMPLOYEE)
    email_is_confirmed = models.BooleanField(default=False)
    confirmation_token = models.CharField(max_length=100, null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return str(self.email)

    objects = CustomUserManager()

    # for user token
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    def generate_confirmation_token(self):
        return secrets.token_urlsafe(30)  # Adjust the length as needed

    class Meta:
        permissions = [
            ("view_user_profile", "Can view user profile"),
        ]


class OTP(TimeStampedModel):
    user = models.OneToOneField(BaseUser, on_delete=models.CASCADE, related_name='otp')
    code = models.CharField(max_length=6)
    created = models.DateTimeField(default=datetime.now())

    def __str__(self):
        return f"{self.user.email} - {self.code}"
