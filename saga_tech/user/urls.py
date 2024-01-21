from django.urls import path

from .views import UserRegistrationView, UserLoginView, UserVerifyOTPView, UserVerifyEmailView, PasswordResetView, \
    PasswordResetConfirmView, UserUpdateView, ListManagerAndEmployeeView, UserTokenRefreshView

urlpatterns = [
    path('register', UserRegistrationView.as_view(), name='user-registration'),
    path('login', UserLoginView.as_view(), name='user-login'),
    path('verify', UserVerifyOTPView.as_view(), name='user-otp-verify'),
    path('confirm-email', UserVerifyEmailView.as_view(), name='user-otp-email'),
    path('password-reset', PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/confirm', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('update', UserUpdateView.as_view(), name='user-update'),
    path('list-user', ListManagerAndEmployeeView.as_view(), name='user-update'),
    path('token/refresh', UserTokenRefreshView.as_view(), name='token_refresh'),
]