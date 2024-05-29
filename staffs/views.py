from django.conf import settings
from rest_framework.generics import ListAPIView
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from rest_framework import permissions
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from customers.models import PersonalLoan, TargetSaving, LeaseFinancing, CorporateLoan
from customers.serializers import PersonalLoanSerializer, TargetSavingSerializer, LeaseFinancingSerializer, CorporateLoanSerializer, GetPersonalLoanSerializer, GetTargetSavingSerializer, GetLeaseFinancingSerializer, GetCorporateLoanSerializer
from rest_framework.parsers import MultiPartParser, FormParser
from accounts.permissions import IsAdminorCustomer, IsAdmin
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from django.core.validators import validate_email
from django.template.loader import render_to_string
from accounts.utils import Util
from django.utils.translation import gettext_lazy as _
from accounts.exceptions import CustomException
from accounts.models import User
from accounts.serializers import ProfileSerializer


# ======================================STATIC PAGE SECTIONS==============================================
def personalLoans(request):
    return render(request, 'staffs/personalLoans.html')


def targetSavings(request):
    return render(request, 'staffs/target_savings.html')


def LeaseFinancings(request):
    return render(request, 'staffs/LeaseFinancings.html')


def CorporateLoans(request):
    return render(request, 'staffs/CorporateLoans.html')

# ============================================DeactivateAccountAPIView====================================


class DeactivateAccountAPIView(APIView):
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["User Management"],
        operation_summary="Deactivate User Account",
        operation_description="Deactivate the authenticated user's account.",
        responses={
            200: "User deactivated successfully.",
            403: "Forbidden. You do not have permission to deactivate this account."
        }
    )
    def patch(self, request, *args, **kwargs):
        # Get the authenticated user
        user = request.user

        # Check if the user ID in the URL matches the authenticated user's ID
        user_id = kwargs.get('user_id')
        if str(user_id) != str(user.id):
            return Response({'error': 'You do not have permission to deactivate this account.'}, status=status.HTTP_403_FORBIDDEN)

        # Deactivate the user's account
        user.is_active = False
        user.save()

        # ===============================================================================================================#
        return Response({'success': True, 'message': 'User deactivated successfully'}, status=status.HTTP_200_OK)


class ListRegisteredUsersAPIView(APIView):
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="List Registered Users",
        operation_description="List all registered users.",
        responses={
            200: openapi.Response(description="List of registered users", schema=ProfileSerializer(many=True)),
            401: "Unauthorized"
        }
    )
    def get(self, request, *args, **kwargs):
        try:
            users = User.objects.all()
            user_serializer = ProfileSerializer(users, many=True)
            user_count = users.count()

            user_data = []
            for user in users:
                user_profile = user.profile
                profile_serializer = ProfileSerializer(user_profile)
                user_data.append({
                    "id": user.id,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "email": user.email,
                    "user_type": user.user_type,
                    "is_active": user.is_active,
                    "profile_picture": profile_serializer.data.get("profile_picture"),
                    "state": profile_serializer.data.get("state"),
                    "city": profile_serializer.data.get("city"),
                    "country": profile_serializer.data.get("country"),
                    "address": profile_serializer.data.get("address"),
                    "sex": profile_serializer.data.get("sex"),
                    "dob": profile_serializer.data.get("dob"),
                    "phone_number": profile_serializer.data.get("phone_number"),
                    "created_at": profile_serializer.data.get("created_at"),
                    "updated_at": profile_serializer.data.get("updated_at")
                })

            response_data = {
                "status": status.HTTP_200_OK,
                "message": "List of registered users",
                "count": user_count,
                "data": user_data
            }
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AllPersonalLoanListAPIView(APIView):
    serializer_class = GetPersonalLoanSerializer
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="List All Personal Loans",
        operation_description="Retrieve all personal loans created by any user.",
        responses={
            200: GetPersonalLoanSerializer(many=True),
            401: "Unauthorized"
        }
    )
    def get(self, request, *args, **kwargs):
        # Retrieve all personal loans
        personal_loans = PersonalLoan.objects.all()

        # Get the count of personal loans
        loan_count = personal_loans.count()

        serializer = self.serializer_class(personal_loans, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "All personal loans retrieved successfully",
            "count": loan_count,
            "data": {
                "loans": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class AllTargetSavingListAPIView(APIView):
    serializer_class = GetTargetSavingSerializer
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="List All Target Savings",
        operation_description="Retrieve all target savings created by any user.",
        responses={
            200: GetTargetSavingSerializer(many=True),
            401: "Unauthorized"
        }
    )
    def get(self, request, *args, **kwargs):
        # Retrieve all target savings
        target_savings = TargetSaving.objects.all()

        # Get the count of target savings
        saving_count = target_savings.count()

        serializer = self.serializer_class(target_savings, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "All target savings retrieved successfully",
            "count": saving_count,
            "data": {
                "savings": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class AllLeaseFinancingListAPIView(APIView):
    serializer_class = GetLeaseFinancingSerializer
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="List All Lease Financings",
        operation_description="Retrieve all lease financings created by any user.",
        responses={
            200: GetLeaseFinancingSerializer(many=True),
            401: "Unauthorized"
        }
    )
    def get(self, request, *args, **kwargs):
        # Retrieve all lease financings
        lease_financings = LeaseFinancing.objects.all()

        # Get the count of lease financings
        financing_count = lease_financings.count()

        serializer = self.serializer_class(lease_financings, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "All lease financings retrieved successfully",
            "count": financing_count,
            "data": {
                "financings": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class AllCorporateLoanListAPIView(APIView):
    serializer_class = GetCorporateLoanSerializer
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="List All Corporate Loans",
        operation_description="Retrieve all corporate loans created by any user.",
        responses={
            200: GetCorporateLoanSerializer(many=True),
            401: "Unauthorized"
        }
    )
    def get(self, request, *args, **kwargs):
        # Retrieve all corporate loans
        corporate_loans = CorporateLoan.objects.all()

        # Get the count of corporate loans
        loan_count = corporate_loans.count()

        serializer = self.serializer_class(corporate_loans, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "All corporate loans retrieved successfully",
            "count": loan_count,
            "data": {
                "loans": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class StatsAPIView(APIView):
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="Get Statistics",
        operation_description="Retrieve statistics about the system, including customer count, personal loan count, corporate loan count, lease financing count, and target saving count.",
        responses={
            200: openapi.Response(
                description="Statistics retrieved successfully",
                examples={
                    'application/json': {
                        "status": status.HTTP_200_OK,
                        "message": "Statistics retrieved successfully",
                        "data": {
                            "customer_count": 0,
                            "personal_loan_count": 0,
                            "corporate_loan_count": 0,
                            "lease_financing_count": 0,
                            "target_saving_count": 0
                        }
                    }
                }
            ),
            401: "Unauthorized"
        }
    )
    def get(self, request, *args, **kwargs):
        customer_count = User.objects.filter(user_type='CUSTOMER').count()
        personal_loan_count = PersonalLoan.objects.count()
        corporate_loan_count = CorporateLoan.objects.count()
        lease_financing_count = LeaseFinancing.objects.count()
        target_saving_count = TargetSaving.objects.count()

        data = {
            "customer_count": customer_count,
            "personal_loan_count": personal_loan_count,
            "corporate_loan_count": corporate_loan_count,
            "lease_financing_count": lease_financing_count,
            "target_saving_count": target_saving_count
        }

        response = {
            "status": status.HTTP_200_OK,
            "message": "Statistics retrieved successfully",
            "data": data
        }

        return Response(response, status=status.HTTP_200_OK)
