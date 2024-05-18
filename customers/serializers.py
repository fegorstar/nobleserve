from .models import PersonalLoan
from rest_framework import serializers
from .models import Profile
from accounts.models import User
from django.conf import settings


class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False)
    user_type = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'user_type', 'is_active']


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


class PersonalLoanSerializer(serializers.ModelSerializer):
    transaction_id = serializers.ReadOnlyField()

    class Meta:
        model = PersonalLoan
        fields = ['transaction_id', 'sex', 'dob', 'address',
                  'occupation', 'purpose_of_loan', 'amount', 'duration']
        read_only_fields = ['transaction_id', 'status']


class GetPersonalLoanSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()
    user_id = serializers.SerializerMethodField()

    class Meta:
        model = PersonalLoan
        fields = ['transaction_id', 'sex', 'status', 'dob', 'address',
                  'occupation', 'purpose_of_loan', 'amount', 'duration', 'created_at', 'modified_at', 'customer_name', 'user_id']

    def get_customer_name(self, obj):
        return obj.created_by.get_full_name() if obj.created_by.get_full_name() else obj.created_by.username

    def get_user_id(self, obj):
        return obj.created_by.id
