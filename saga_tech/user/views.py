from rest_framework import status
from rest_framework.decorators import permission_classes
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenRefreshView

from .models import BaseUser
from .permissions import IsOwnerOrReadOnly, IsAdminUser
from .serializers import UserRegistrationSerializer, LoginSerializer, PasswordResetSerializer, \
    UserUpdateSerializer, ManagerEmployeeListSerializer, CustomTokenRefreshSerializer
from .service import authenticate_user, is_valid_otp, get_tokens, is_valid_email_secret, \
    remove_email_secret, generate_otp, save_and_send_opt_over_mail, remove_otp, get_manager_and_employee_list


class UserRegistrationView(APIView):
    serializer_class = UserRegistrationSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)

            if serializer.is_valid(raise_exception=True):
                serializer.save()
                status_code = status.HTTP_201_CREATED

                response = {
                    'success': True,
                    'statusCode': status_code,
                    'message': 'User successfully registered!',
                    'email': serializer.data.get('email'),
                    'role': serializer.data.get('role'),
                }

                return Response(response, status=status_code)
        except Exception as e:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"errors": {"display_error": str(e), "internal_error_code": 400}}
            )


class UserLoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid(raise_exception=True):
                credentials = serializer.data
                response = authenticate_user(credentials)
                if isinstance(response, dict) or response.status_code == status.HTTP_200_OK:
                    status_code = status.HTTP_200_OK
                    response = {
                        'success': True,
                        'statusCode': status_code,
                        'message': response.get('status')
                    }
                    return Response(response, status=status_code)
                else:
                    return Response(
                        status=status.HTTP_400_BAD_REQUEST,
                        data={
                            "errors": {
                                "display_error": f"{response.data['errors']['display_error']}",
                                "internal_error_code": 400}
                        }
                    )
        except Exception as e:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "errors": {
                        "display_error": str(e), "internal_error_code": 400}
                }
            )


class UserTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer


class UserVerifyOTPView(APIView):
    def post(self, request):
        try:
            otp = request.data.get("otp")
            user = is_valid_otp(otp)
            access_token, refresh_token = get_tokens(user)
            response = {
                'success': True,
                'statusCode': status.HTTP_200_OK,
                'message': 'User Logged in!',
                'email': user.email,
                'access_token': access_token,
                'refresh_token': refresh_token,
            }
            return Response(response, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "errors": {
                        "display_error": str(e), "internal_error_code": 400}
                }
            )


class UserVerifyEmailView(APIView):
    def post(self, request):
        try:
            email_secret_code = request.data.get("email_secret_code")
            if email_secret_code:
                user, success = is_valid_email_secret(email_secret_code)
                if success:
                    remove_email_secret(user)
                    response = {
                        'success': True,
                        'statusCode': status.HTTP_200_OK,
                        'message': 'User email is verified!',
                        'email': user.email,
                    }
                    return Response(response, status=status.HTTP_200_OK)
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "errors": {
                        "display_error": "Email secret code can not be empty",
                        "internal_error_code": 400}
                }
            )
        except Exception as e:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "errors": {
                        "display_error": str(e), "internal_error_code": 400}
                }
            )


class PasswordResetView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        if not email:
            return Response({'detail': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = BaseUser.objects.get(email=email)
            otp = generate_otp()
            save_and_send_opt_over_mail(user, otp)
        except User.DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'detail': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    def post(self, request, *args, **kwargs):
        otp = request.data.get('otp')
        password = request.data.get('password')

        if not otp or not password:
            return Response({'detail': 'OTP and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = is_valid_otp(otp)
        except Exception as e:
            print(e)
            return Response({'detail': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(password)
        user.save()
        remove_otp(user)
        return Response({'detail': 'Password reset successfully.'}, status=status.HTTP_200_OK)


@permission_classes([IsAuthenticated])
class UserUpdateView(APIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [IsOwnerOrReadOnly]

    def post(self, request):
        try:
            serializer = self.serializer_class(self.request.user, request.data)

            if serializer.is_valid(raise_exception=True):
                serializer.save()

                status_code = status.HTTP_200_OK

                response = {
                    'success': True,
                    'statusCode': status_code,
                    'message': 'User data successfully updated!',
                    'email': self.request.user.email,
                    'role': self.request.user.role,
                }

                return Response(response, status=status_code)
        except Exception as e:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"errors": {"display_error": str(e), "internal_error_code": 400}}
            )

class ListManagerAndEmployeeView(GenericAPIView):
    serializer_class = ManagerEmployeeListSerializer
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            manager_list, employee_list = get_manager_and_employee_list()
            return Response(
                status=status.HTTP_200_OK,
                data={
                    "manager_list": manager_list,
                    "employee_list": employee_list
                }
            )
        except Exception as e:
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"errors": {"display_error": str(e), "internal_error_code": 400}}
            )
