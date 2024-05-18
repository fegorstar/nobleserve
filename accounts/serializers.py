from rest_framework_simplejwt.tokens import TokenError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()

    def create(self, validated_data):
        """
        Create and return a new user instance, given the validated data.
        """
        return User.objects.create_user(**validated_data)


class VerificationRequestSerializer(serializers.Serializer):
    verification_code = serializers.CharField()


class ResendVerificationCodeSerializer(serializers.Serializer):
    email = serializers.EmailField()


class EmailVerificationSerializer(serializers.Serializer):
    verification_code = serializers.CharField(max_length=6)


# ============================Updated LoginSerializer========================================
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)

    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = obj
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return {
            'refresh': refresh_token,
            'access': access_token,
        }


# ========================LogoutSerializer===================
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            # No need to blacklist the token here
            pass
        except TokenError:
            raise AuthenticationFailed('Token is expired or invalid', 401)


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True
    )
    token = serializers.CharField(
        min_length=1, write_only=True
    )
    uidb64 = serializers.CharField(
        min_length=1, write_only=True
    )

    def update_password(self, user, validated_data):
        password = validated_data.get('password')

        # Set password for the user
        user.set_password(password)
        user.save()

    def validate(self, attrs):
        try:
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            # Decoding uidb64 within the correct schema context
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed(
                    'The reset link is invalid', 401)

            return attrs

        except User.DoesNotExist:
            raise AuthenticationFailed(
                'User not found', 401)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
