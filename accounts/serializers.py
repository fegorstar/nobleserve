from rest_framework_simplejwt.tokens import TokenError
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers
from .models import User
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.conf import settings
from customers.models import Profile

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()

    def validate_email(self, value):
        """
        Ensure the email is always in lowercase.
        """
        return value.lower()

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


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    user_type = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'user_type', 'is_active']


class ProfileUpdateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(
        source='user.first_name', required=False)
    last_name = serializers.CharField(
        source='user.last_name', required=False)
    country = serializers.CharField(required=True)
    phone_number = serializers.CharField(required=True)

    class Meta:
        model = Profile
        fields = ['first_name', 'last_name', 'profile_picture', 'country', 'state', 'city', 'sex', 'dob', 'address',
                  'phone_number']
        # Specify read-only fields here
        read_only_fields = ['user_id', 'email']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        if user_data:
            user = instance.user
            user.email = user_data.get('email', user.email)
            user.first_name = user_data.get('first_name', user.first_name)
            user.last_name = user_data.get('last_name', user.last_name)
            user.save()

        # Remove previous profile picture before updating with new one
        profile_picture = validated_data.get('profile_picture')
        if profile_picture:
            instance.profile_picture.delete(save=False)

        instance.profile_picture = self.context['request'].FILES.get(
            'profile_picture', instance.profile_picture)

        instance.state = validated_data.get('state', instance.state)
        instance.city = validated_data.get('city', instance.city)
        instance.country = validated_data.get(
            'country', instance.country)
        instance.phone_number = validated_data.get(
            'phone_number', instance.phone_number)
        instance.sex = validated_data.get(
            'sex', instance.sex)
        instance.dob = validated_data.get(
            'dob', instance.dob)
        instance.address = validated_data.get(
            'address', instance.address)

        instance.save()
        return instance


class ProfileSerializer(serializers.ModelSerializer):
    # Assuming you want to include user details
    user = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = Profile
        fields = ['user', 'profile_picture', 'state', 'city', 'country', 'address', 'sex', 'dob',
                  'phone_number', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']

    def get_user(self, obj):
        user = obj.user
        return {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'user_type': user.user_type,
            'is_active': user.is_active,
            # Add other user details as needed
        }

    def get_profile_picture(self, obj):
        if obj.profile_picture:
            return f"{settings.BASE_URL}{obj.profile_picture.url}"
        return None


class EmailChangeSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(min_length=6, max_length=68)


class PasswordChangeSerializer(serializers.Serializer):
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
