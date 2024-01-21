from django.contrib.auth.models import BaseUserManager
from django.core.mail import send_mail


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        from .models import BaseUser

        if not email:
            raise ValueError(_("The email must be set"))
        if not password:
            raise ValueError(_("The password must be set"))
        email = self.normalize_email(email)
        groups = extra_fields.pop('groups', [])
        user_permissions = extra_fields.pop('user_permissions', [])

        user = self.model(email=email, **extra_fields)
        user.is_active = True
        user.set_password(password)
        user.confirmation_token = user.generate_confirmation_token()
        send_mail(
            "Email confirmation",
            f"Please confirm your mail - {user.confirmation_token}",
            "sagar.k@thinkwik.com",
            [user.email],
            fail_silently=False,
        )
        user.save()

        user.groups.set(groups)
        user.user_permissions.set(user_permissions)

        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', BaseUser.RoleChoice.ADMIN)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        if extra_fields.get('role') != 1:
            raise ValueError('Superuser must have role of Global Admin')
        return self.create_user(email, password, **extra_fields)
