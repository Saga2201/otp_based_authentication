from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from rest_framework_simplejwt.serializers import TokenRefreshSerializer

from .models import BaseUser


class UserRegistrationSerializer(ModelSerializer):
    class Meta:
        model = BaseUser
        fields = '__all__'

    def create(self, validated_data):
        try:
            user = BaseUser.objects.create_user(**validated_data)
            return user
        except Exception as e:
            raise serializers.ValidationError({"Error": f"{e}"})


class LoginSerializer(serializers.Serializer):
    """
    login serializer.
    """
    email = serializers.EmailField()
    password = serializers.CharField()


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()


class UserUpdateSerializer(ModelSerializer):
    class Meta:
        model = BaseUser
        fields = ['first_name', 'last_name', 'phone_number', 'password']

    def update(self, instance, validated_data):
        try:
            instance.first_name = validated_data.get('first_name', instance.first_name)
            instance.last_name = validated_data.get('last_name', instance.last_name)
            instance.phone_number = validated_data.get('phone_number', instance.phone_number)
            instance.set_password(validated_data.get('password', instance.password))
            instance.save()
            return instance
        except Exception as e:
            raise serializers.ValidationError({"Error": f"{e}"})


class ManagerEmployeeListSerializer(serializers.Serializer):
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    email = serializers.EmailField()
    phone_number = PhoneNumberField()


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super(CustomTokenRefreshSerializer, self).validate(attrs)
        return {
            "access_token": data.get('access'),
            "refresh_token": data.get('refresh')
        }