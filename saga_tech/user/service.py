import os
import random
import string
from datetime import datetime, timedelta, timezone

from django.contrib.auth import authenticate
from dotenv import load_dotenv
from rest_framework import status
from rest_framework.response import Response
from twilio.rest import Client
from utils.custom_error import FailedToLogin, OTPExpired

from .models import OTP, BaseUser
from .serializers import ManagerEmployeeListSerializer

load_dotenv()


def generate_otp(length=6):
    """
    function generate otp.
    :param length:
    :return:
    """
    characters = string.digits
    otp = ''.join(random.choice(characters) for _ in range(length))
    return otp


def authenticate_user(credentials: dict) -> dict:
    """
    function will check user credentials.
    :param credentials: contains username and password
    :return: user email, access_token, and refresh_token
    """
    try:
        user = authenticate(email=credentials['email'], password=credentials['password'])
        if user:
            otp = generate_otp()
            message = send_top(user.phone_number, otp)
            if message.status == "queued":
                otp_instance, created = OTP.objects.get_or_create(user=user)
                otp_instance.code = otp
                otp_instance.created = datetime.now()
                otp_instance.save()
            return {
                "email": user.email,
                "status": "OTP sent"
            }
        raise FailedToLogin("Unable to log in with provided credentials.")

    except Exception as e:
        return Response(
            status=status.HTTP_400_BAD_REQUEST,
            data={
                "errors": {
                    "display_error": f"{e}",
                    "internal_error_code": 400}
            }
        )


def send_top(mobile_number: int, otp: int):
    """
    function will send OTP to user mobile number.
    :param mobile_number:
    :param otp:
    :return:
    """
    try:
        account_sid = os.getenv('TW_ACCOUNT_SID')
        auth_token = os.getenv('TW_AUTH_TOKEN')
        twilio_phone_number = os.getenv('TW_PHONE_NUMBER')

        client = Client(account_sid, auth_token)
        print("OTP: ", otp)
        message = client.messages.create(
            body=f'Your OTP is: {otp}',
            from_=twilio_phone_number,
            to=f"+91{mobile_number}"
        )
        return message
    except Exception as e:
        return Response(
            status=status.HTTP_400_BAD_REQUEST,
            data={
                "errors": {
                    "display_error": f"{e}",
                    "internal_error_code": 400}
            }
        )


def is_valid_otp(otp: int) -> BaseUser:
    """
    function will check whether given otp is valid or not.
    :param otp: contains otp code.
    :return: BaseUser object
    """
    otp_instance = OTP.objects.get(code=otp)
    naive_now = datetime.now(timezone.utc)
    aware_created = otp_instance.created.replace(tzinfo=timezone.utc) + timedelta(minutes=15)
    if naive_now > aware_created:
        print("OTP is expired")
        raise OTPExpired("Provided OTP is expired!")
    remove_otp(otp_instance.user)
    return otp_instance.user


def get_tokens(user: BaseUser) -> dict:
    """
    function return access_token and refresh_token
    :param user:
    :return:
    """
    tokens = user.tokens()
    return tokens['access'], tokens['refresh']


def is_valid_email_secret(email_secret: str) -> [BaseUser, bool]:
    """
    function will check email secret on email confirmation.
    :param email_secret: str
    :return: user instance(BaseUser), Boolean value
    """
    user_instance = BaseUser.objects.filter(confirmation_token=email_secret).first()
    if not user_instance:
        raise OTPExpired("Email secret is not valid!")
    return user_instance, True


def remove_email_secret(user: BaseUser) -> None:
    """
    function will remove secret email code once it's get verified.
    :param user: user object
    :return: None
    """
    user.confirmation_token = ""
    user.save()


def save_and_send_opt_over_mail(user: BaseUser, otp: int) -> None:
    """
    function will save user otp and send it over mail.
    :param user: user object
    :param otp: otp
    :return: None
    """
    try:
        OTP.objects.update_or_create(user=user, defaults={'code': otp, 'created': datetime.now()})
        send_otp_email_over_mail(otp, user.email)
    except Exception as e:
        return Response(
            status=status.HTTP_400_BAD_REQUEST,
            data={
                "errors": {
                    "display_error": f"{e}",
                    "internal_error_code": 400}
            }
        )


def remove_otp(user: BaseUser) -> None:
    """
    function will remove user otp once it get used.
    :param user: user object
    :return: None
    """
    try:
        otp = OTP.objects.filter(user=user)
        if otp:
            otp.first().delete()
    except Exception as e:
        return Response(
            status=status.HTTP_400_BAD_REQUEST,
            data={
                "errors": {
                    "display_error": f"{e}",
                    "internal_error_code": 400}
            }
        )


def get_manager_and_employee_list():
    """
    function return manager and employee list.
    :return:
    """
    manager = BaseUser.objects.filter(role="Employee")
    employee = BaseUser.objects.filter(role="Manager")
    manager_list = ManagerEmployeeListSerializer(manager, many=True).data
    employee_list = ManagerEmployeeListSerializer(employee, many=True).data

    return manager_list, employee_list


def send_otp_email_over_mail(otp: int, email: str) -> None:
    """
    function send opt over mail for password reset confirmation otp.
    by using given otp customer can update his/her password.
    :param otp: int (329123)
    :param email: str
    :return: None
    """
    reset_link = "http://127.0.0.1:8000/user/password-reset/confirm"
    subject = 'Password Reset'
    message = f"Click on the following link to reset your password: {reset_link} \n " \
              f"User OTP while resetting the password: {otp}"
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list)
