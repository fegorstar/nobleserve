from django.core.exceptions import ValidationError
from .models import PersonalLoan, TargetSaving, LeaseFinancing, CorporateLoan
from rest_framework import serializers
from accounts.models import User
from django.conf import settings


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


class TargetSavingSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetSaving
        fields = ['transaction_id', 'amount', 'start_save',
                  'save_by', 'status', 'created_at', 'modified_at']
        read_only_fields = ['transaction_id',
                            'created_at', 'modified_at',  'status']

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        rep['created_by'] = instance.created_by.email if instance.created_by else ''
        return rep


class GetTargetSavingSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()
    user_id = serializers.SerializerMethodField()

    class Meta:
        model = TargetSaving
        fields = ['transaction_id', 'created_by', 'amount', 'start_save', 'save_by',
                  'status', 'created_at', 'modified_at', 'customer_name', 'user_id']
        read_only_fields = ['transaction_id', 'created_at',
                            'modified_at', 'customer_name', 'user_id']

    def get_customer_name(self, obj):
        return obj.created_by.get_full_name() if obj.created_by.get_full_name() else obj.created_by.username

    def get_user_id(self, obj):
        return obj.created_by.id


class LeaseFinancingSerializer(serializers.ModelSerializer):
    class Meta:
        model = LeaseFinancing
        fields = ['transaction_id', 'equipment_type', 'equipment_amount', 'has_funding',
                  'acquisition_timeline', 'has_documents', 'document_link', 'repayment_duration', 'location', 'status']
        read_only_fields = ['transaction_id',
                            'created_at', 'modified_at', 'status']

    def validate(self, data):
        if data.get('has_documents') == LeaseFinancing.YES and not data.get('document_link'):
            raise ValidationError(
                {"document_link": "This field is required when documents are provided."})
        return data


class GetLeaseFinancingSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()
    user_id = serializers.SerializerMethodField()

    class Meta:
        model = LeaseFinancing
        fields = ['transaction_id', 'created_by', 'equipment_type', 'equipment_amount', 'has_funding', 'acquisition_timeline',
                  'has_documents', 'document_link', 'repayment_duration', 'location', 'customer_name', 'user_id', 'status']
        read_only_fields = ['transaction_id', 'created_at',
                            'modified_at', 'customer_name', 'user_id']

    def get_customer_name(self, obj):
        return obj.created_by.get_full_name() if obj.created_by.get_full_name() else obj.created_by.username

    def get_user_id(self, obj):
        return obj.created_by.id


class CorporateLoanSerializer(serializers.ModelSerializer):
    class Meta:
        model = CorporateLoan
        fields = ['transaction_id', 'business_age', 'industry', 'loan_purpose',
                  'loan_amount', 'has_documents', 'document_link', 'repayment_duration', 'status']
        read_only_fields = ['transaction_id',
                            'created_at', 'modified_at', 'status']

    def validate(self, data):
        if data.get('has_documents') == CorporateLoan.YES and not data.get('document_link'):
            raise ValidationError(
                {"document_link": "This field is required when documents are provided."})
        return data


class GetCorporateLoanSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()
    user_id = serializers.SerializerMethodField()

    class Meta:
        model = CorporateLoan
        fields = ['transaction_id', 'created_by', 'business_age', 'industry', 'loan_purpose', 'loan_amount',
                  'has_documents', 'document_link', 'repayment_duration', 'customer_name', 'user_id', 'status']
        read_only_fields = ['transaction_id', 'created_at',
                            'modified_at', 'customer_name', 'user_id']

    def get_customer_name(self, obj):
        return obj.created_by.get_full_name() if obj.created_by.get_full_name() else obj.created_by.username

    def get_user_id(self, obj):
        return obj.created_by.id
