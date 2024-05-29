from django.conf import settings
from rest_framework.generics import ListAPIView
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from rest_framework import permissions
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Profile, PersonalLoan, TargetSaving, LeaseFinancing, CorporateLoan
from .serializers import PersonalLoanSerializer, TargetSavingSerializer, LeaseFinancingSerializer, CorporateLoanSerializer, GetPersonalLoanSerializer, GetTargetSavingSerializer, GetLeaseFinancingSerializer, GetCorporateLoanSerializer
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


# =========================================STATIC PAGES======================================================================
def profile(request):
    return render(request, 'customers/profile.html')


def personalloans(request):
    return render(request, 'customers/mypersonalloans.html')


def myTargetSavings(request):
    return render(request, 'customers/myTargetSavings.html')


def myleaseFinancings(request):
    return render(request, 'customers/myleaseFinancings.html')


def mycorporateLoans(request):
    return render(request, 'customers/mycorporateLoans.html')


# ========================================ENdpointssection=============================================

# ========================================PersonalLoan=============================================


class PersonalLoanCreateAPIView(APIView):
    serializer_class = PersonalLoanSerializer
    permission_classes = [IsAdminorCustomer]
    parser_classes = [MultiPartParser, FormParser]

    @staticmethod
    def send_loan_creation_notification(user, loan):
        email_subject = 'New Personal Loan Created'
        email_body = render_to_string('email_templates/loan_creation_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'user_email': user.email,
            'loan_details': loan,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @staticmethod
    def send_followup_email(user):
        email_subject = 'Thank You for Your Loan Application'
        email_body = render_to_string('email_templates/followup_email.html', {
            'user_full_name': f'{user.first_name} {user.last_name}', 'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @swagger_auto_schema(
        tags=['Personal Loan Management'],
        operation_summary="Create Personal Loan",
        operation_description="Create a new personal loan.",
        request_body=PersonalLoanSerializer,
        responses={
            201: openapi.Response(description="Personal loan created successfully"),
            400: openapi.Response(description="Bad request"),
            500: openapi.Response(description="Internal server error"),
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        try:
            if serializer.is_valid():
                # Assuming you want to associate the loan with the current user
                loan = serializer.save(created_by=request.user)

                # Get admin users
                admin_users = User.objects.filter(user_type='ADMIN')

                # Send notification email to admin users
                for admin_user in admin_users:
                    self.send_loan_creation_notification(admin_user, loan)

                # Send follow-up email to the user
                self.send_followup_email(request.user)

                response_data = {
                    "status": status.HTTP_201_CREATED,
                    "message": "Personal loan created successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=response_data["status"])
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=response_data["status"])
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=response_data["status"])


class UserPersonalLoanListAPIView(APIView):
    serializer_class = GetPersonalLoanSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Personal Loan Management"],
        operation_summary="List User's Personal Loans",
        operation_description="Retrieve personal loans created by the specified user.",
        responses={
            200: GetPersonalLoanSerializer(many=True),
            401: "Unauthorized",
            404: "User not found"
        }
    )
    def get(self, request, user_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)

        # Retrieve personal loans created by the specified user
        personal_loans = PersonalLoan.objects.filter(created_by=user)

        # Get the count of personal loans
        loan_count = personal_loans.count()

        serializer = self.serializer_class(personal_loans, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Personal loans retrieved successfully",
            "count": loan_count,
            "data": {

                "loans": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class UserPersonalLoanDetailAPIView(APIView):
    serializer_class = GetPersonalLoanSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Personal Loan Management"],
        operation_summary="Retrieve a User's Personal Loan",
        operation_description="Retrieve details of a specific personal loan created by the specified user.",
        responses={
            200: GetPersonalLoanSerializer(),
            401: "Unauthorized",
            403: "Forbidden",
            404: "Loan not found"
        }
    )
    def get(self, request, user_id, loan_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)
        # Retrieve the specific personal loan created by the specified user
        personal_loan = get_object_or_404(
            PersonalLoan, transaction_id=loan_id, created_by=user)

        serializer = self.serializer_class(personal_loan)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Personal loan retrieved successfully",
            "data": serializer.data
        }
        return Response(response_data, status=status.HTTP_200_OK)


class PersonalLoanUpdateAPIView(APIView):
    serializer_class = PersonalLoanSerializer
    permission_classes = [IsAdminorCustomer]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        tags=["Personal Loan Management"],
        operation_summary="Update User's Personal Loan",
        operation_description="Update the specified personal loan of the authenticated user.",
        request_body=PersonalLoanSerializer,
        responses={
            200: openapi.Response(description="Personal loan updated successfully"),
            400: openapi.Response(description="Bad request"),
            403: openapi.Response(description="Forbidden"),
            404: openapi.Response(description="Personal loan not found"),
        }
    )
    def put(self, request, loan_id, *args, **kwargs):
        # Retrieve the personal loan or return 404 if not found
        loan = get_object_or_404(PersonalLoan, transaction_id=loan_id)

        # Check if the current user is the creator of the loan or is an admin
        if loan.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(
            loan, data=request.data, partial=True)

        try:
            if serializer.is_valid():
                serializer.save()
                response_data = {
                    "status": status.HTTP_200_OK,
                    "message": "Personal loan updated successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PersonalLoanDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        tags=["Personal Loan Management"],
        operation_summary="Delete User's Personal Loan",
        operation_description="Delete the specified personal loan of the authenticated user.",
        responses={
            200: "Personal loan deleted successfully",
            403: "Forbidden",
            404: "Personal loan not found",
        }
    )
    def delete(self, request, loan_id, *args, **kwargs):
        # Retrieve the personal loan or raise a 404 error if not found
        try:
            loan = PersonalLoan.objects.get(transaction_id=loan_id)
        except PersonalLoan.DoesNotExist:
            raise Http404("Personal loan does not exist")

        # Check if the current user is the creator of the loan or is an admin
        if loan.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        # Delete the loan
        loan.delete()

        return Response({"status": status.HTTP_200_OK, "message": "Personal loan deleted successfully", "data": None}, status=status.HTTP_200_OK)


class PersonalLoanStatusUpdateAPIView(APIView):
    permission_classes = [IsAdmin]

    def send_loan_update_notification(self, user, loan):
        status_messages = {
            'Pending': 'Your loan application is pending.',
            'Processing': 'Your loan application is being processed.',
            'Declined': 'Your loan application has been declined.',
            'Paid': 'Your loan has been approved and paid.'
        }
        email_subject = 'Personal Loan Status Updated'
        email_body = render_to_string('email_templates/loan_update_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'loan_details': loan,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
            'status_message': status_messages.get(loan.status, 'Your loan application status has been updated.')
        })
        data = {
            'to_email': user.email,
            'email_subject': email_subject,
            'email_body': email_body
        }
        Util.send_email(data)

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="Update Personal Loan Status",
        operation_description="Update the status of a personal loan.",
        manual_parameters=[
            openapi.Parameter(
                name="loan_id",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="ID of the loan to be updated"
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_STRING, description="New status for the loan")
            }
        ),
        responses={
            200: openapi.Response(description="Loan status updated successfully"),
            400: openapi.Response(description="Bad request"),
            404: openapi.Response(description="Loan not found"),
            403: openapi.Response(description="Forbidden"),
        }
    )
    def patch(self, request, loan_id):
        try:
            loan = PersonalLoan.objects.get(transaction_id=loan_id)
        except PersonalLoan.DoesNotExist:
            return Response({"status": status.HTTP_404_NOT_FOUND, "message": "Loan not found"}, status=status.HTTP_404_NOT_FOUND)

        new_status = request.data.get('status')

        if new_status not in dict(PersonalLoan.transaction_status_choices).keys():
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        previous_status = loan.status  # Store previous status for email notification

        loan.status = new_status
        loan.save()

        # Send email notification to the user
        self.send_loan_update_notification(loan.created_by, loan)

        return Response({"status": status.HTTP_200_OK, "message": "Loan status updated successfully"}, status=status.HTTP_200_OK)


# ===========================================TARGET SAVINGS================================================

class TargetSavingCreateAPIView(APIView):
    serializer_class = TargetSavingSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAdminorCustomer]

    @staticmethod
    def send_saving_creation_notification(user, saving):
        email_subject = 'New Target Saving Created'
        email_body = render_to_string('email_templates/saving_creation_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'user_email': user.email,
            'saving_details': saving,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @staticmethod
    def send_followup_email(user):
        email_subject = 'Thank You for Setting Up Your Target Saving'
        email_body = render_to_string('email_templates/followup_email.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @swagger_auto_schema(
        tags=['Target Saving Management'],
        operation_summary="Create Target Saving",
        operation_description="Create a new target saving.",
        request_body=TargetSavingSerializer,
        responses={
            201: openapi.Response(description="Target saving created successfully"),
            400: openapi.Response(description="Bad request"),
            500: openapi.Response(description="Internal server error"),
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        try:
            if serializer.is_valid():
                # Assuming you want to associate the target saving with the current user
                saving = serializer.save(created_by=request.user)

                # Get admin users
                admin_users = User.objects.filter(user_type='ADMIN')

                # Send notification email to admin users
                for admin_user in admin_users:
                    self.send_saving_creation_notification(admin_user, saving)

                # Send follow-up email to the user
                self.send_followup_email(request.user)

                response_data = {
                    "status": status.HTTP_201_CREATED,
                    "message": "Target saving created successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=response_data["status"])
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=response_data["status"])
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=response_data["status"])


class UserTargetSavingListAPIView(APIView):
    serializer_class = GetTargetSavingSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Target Saving Management"],
        operation_summary="List User's Target Savings",
        operation_description="Retrieve target savings created by the specified user.",
        responses={
            200: GetTargetSavingSerializer(many=True),
            401: "Unauthorized",
            404: "User not found"
        }
    )
    def get(self, request, user_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)

        # Retrieve target savings created by the specified user
        target_savings = TargetSaving.objects.filter(created_by=user)

        # Get the count of target savings
        saving_count = target_savings.count()

        serializer = self.serializer_class(target_savings, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Target savings retrieved successfully",
            "count": saving_count,
            "data": {
                "savings": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class TargetSavingDetailAPIView(APIView):
    serializer_class = GetTargetSavingSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Target Saving Management"],
        operation_summary="Retrieve a Target Saving",
        operation_description="Retrieve details of a specific target saving created by the specified user.",
        responses={
            200: GetTargetSavingSerializer(),
            401: "Unauthorized",
            403: "Forbidden",
            404: "Target saving not found"
        }
    )
    def get(self, request, user_id, saving_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)
        # Retrieve the specific target saving created by the specified user
        saving = get_object_or_404(
            TargetSaving, transaction_id=saving_id, created_by=user)

        serializer = self.serializer_class(saving)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Target saving retrieved successfully",
            "data": serializer.data
        }
        return Response(response_data, status=status.HTTP_200_OK)


class TargetSavingUpdateAPIView(APIView):
    serializer_class = TargetSavingSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Target Saving Management"],
        operation_summary="Update Target Saving",
        operation_description="Update the specified target saving of the authenticated user.",
        request_body=TargetSavingSerializer,
        responses={
            200: openapi.Response(description="Target saving updated successfully"),
            400: openapi.Response(description="Bad request"),
            403: openapi.Response(description="Forbidden"),
            404: openapi.Response(description="Target saving not found"),
        }
    )
    def put(self, request, saving_id, *args, **kwargs):
        # Retrieve the target saving or return 404 if not found
        saving = get_object_or_404(TargetSaving, transaction_id=saving_id)

        # Check if the current user is the creator of the saving or is an admin
        if saving.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(
            saving, data=request.data, partial=True)

        try:
            if serializer.is_valid():
                serializer.save()
                response_data = {
                    "status": status.HTTP_200_OK,
                    "message": "Target saving updated successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TargetSavingDeleteAPIView(APIView):
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Target Saving Management"],
        operation_summary="Delete Target Saving",
        operation_description="Delete the specified target saving of the authenticated user.",
        responses={
            200: "Target saving deleted successfully",
            403: "Forbidden",
            404: "Target saving not found",
        }
    )
    def delete(self, request, saving_id, *args, **kwargs):
        # Retrieve the target saving or raise a 404 error if not found
        try:
            saving = TargetSaving.objects.get(transaction_id=saving_id)
        except TargetSaving.DoesNotExist:
            raise Http404("Target saving does not exist")

        # Check if the current user is the creator of the saving or is an admin
        if saving.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        # Delete the saving
        saving.delete()

        return Response({"status": status.HTTP_200_OK, "message": "Target saving deleted successfully", "data": None}, status=status.HTTP_200_OK)


class TargetSavingStatusUpdateAPIView(APIView):
    permission_classes = [IsAdmin]

    def send_saving_update_notification(self, user, saving):
        status_messages = {
            'Pending': 'Your target saving application is pending.',
            'Processing': 'Your target saving application is being processed.',
            'Declined': 'Your target saving application has been declined.',
            'Paid': 'Your target saving has been approved.'
        }
        email_subject = 'Target Saving Status Updated'
        email_body = render_to_string('email_templates/saving_update_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'saving_details': saving,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
            'status_message': status_messages.get(saving.status, 'Your target saving application status has been updated.')
        })
        data = {
            'to_email': user.email,
            'email_subject': email_subject,
            'email_body': email_body
        }
        Util.send_email(data)

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="Update Target Saving Status",
        operation_description="Update the status of a target saving.",
        manual_parameters=[
            openapi.Parameter(
                name="saving_id",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="ID of the saving to be updated"
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_STRING, description="New status for the saving")
            }
        ),
        responses={
            200: openapi.Response(description="Saving status updated successfully"),
            400: openapi.Response(description="Bad request"),
            404: openapi.Response(description="Saving not found"),
            403: openapi.Response(description="Forbidden"),
        }
    )
    def patch(self, request, saving_id):
        try:
            saving = TargetSaving.objects.get(transaction_id=saving_id)
        except TargetSaving.DoesNotExist:
            return Response({"status": status.HTTP_404_NOT_FOUND, "message": "Saving not found"}, status=status.HTTP_404_NOT_FOUND)

        new_status = request.data.get('status')

        if new_status not in dict(TargetSaving.transaction_status_choices).keys():
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        previous_status = saving.status  # Store previous status for notification

        saving.status = new_status
        saving.save()

        # Send email notification to the user
        self.send_saving_update_notification(saving.created_by, saving)

        return Response({"status": status.HTTP_200_OK, "message": "Saving status updated successfully"}, status=status.HTTP_200_OK)
# ================================================================================================================================#


# ==========================================LeaseFinancing==================================================================
class LeaseFinancingCreateAPIView(APIView):
    serializer_class = LeaseFinancingSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAdminorCustomer]

    @staticmethod
    def send_financing_creation_notification(user, financing):
        email_subject = 'New Lease Financing Application Created'
        email_body = render_to_string('email_templates/financing_creation_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'user_email': user.email,
            'financing_details': financing,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @staticmethod
    def send_followup_email(user):
        email_subject = 'Thank You for Your Lease Financing Application'
        email_body = render_to_string('email_templates/followup_email.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @swagger_auto_schema(
        tags=['Lease Financing Management'],
        operation_summary="Create Lease Financing",
        operation_description="Create a new lease financing application.",
        request_body=LeaseFinancingSerializer,
        responses={
            201: openapi.Response(description="Lease financing application created successfully"),
            400: openapi.Response(description="Bad request"),
            500: openapi.Response(description="Internal server error"),
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        try:
            if serializer.is_valid():
                # Assuming you want to associate the lease financing application with the current user
                financing = serializer.save(created_by=request.user)

                # Get admin users
                admin_users = User.objects.filter(user_type='ADMIN')

                # Send notification email to admin users
                for admin_user in admin_users:
                    self.send_financing_creation_notification(
                        admin_user, financing)

                # Send follow-up email to the user
                self.send_followup_email(request.user)

                response_data = {
                    "status": status.HTTP_201_CREATED,
                    "message": "Lease financing application created successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=response_data["status"])
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=response_data["status"])
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=response_data["status"])


class LeaseFinancingListAPIView(APIView):
    serializer_class = GetLeaseFinancingSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Lease Financing Management"],
        operation_summary="List User's Lease Financings",
        operation_description="Retrieve lease financings created by the specified user.",
        responses={
            200: GetLeaseFinancingSerializer(many=True),
            401: "Unauthorized",
            404: "User not found"
        }
    )
    def get(self, request, user_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)

        # Retrieve lease financings created by the specified user
        lease_financings = LeaseFinancing.objects.filter(created_by=user)

        # Get the count of lease financings
        financing_count = lease_financings.count()

        serializer = self.serializer_class(lease_financings, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Lease financings retrieved successfully",
            "count": financing_count,
            "data": {
                "financings": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class LeaseFinancingDetailAPIView(APIView):
    serializer_class = GetLeaseFinancingSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Lease Financing Management"],
        operation_summary="Retrieve a Lease Financing",
        operation_description="Retrieve details of a specific lease financing created by the specified user.",
        responses={
            200: GetLeaseFinancingSerializer(),
            401: "Unauthorized",
            403: "Forbidden",
            404: "Lease financing not found"
        }
    )
    def get(self, request, user_id, financing_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)
        # Retrieve the specific lease financing created by the specified user
        financing = get_object_or_404(
            LeaseFinancing, transaction_id=financing_id, created_by=user)

        serializer = self.serializer_class(financing)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Lease financing retrieved successfully",
            "data": serializer.data
        }
        return Response(response_data, status=status.HTTP_200_OK)


class LeaseFinancingUpdateAPIView(APIView):
    serializer_class = LeaseFinancingSerializer
    permission_classes = [IsAdminorCustomer]
    # Add this line to enable form data parsing
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        tags=["Lease Financing Management"],
        operation_summary="Update Lease Financing",
        operation_description="Update the specified lease financing of the authenticated user.",
        request_body=LeaseFinancingSerializer,
        responses={
            200: openapi.Response(description="Lease financing updated successfully"),
            400: openapi.Response(description="Bad request"),
            403: openapi.Response(description="Forbidden"),
            404: openapi.Response(description="Lease financing not found"),
        }
    )
    def put(self, request, financing_id, *args, **kwargs):
        # Retrieve the lease financing or return 404 if not found
        financing = get_object_or_404(
            LeaseFinancing, transaction_id=financing_id)

        # Check if the current user is the creator of the financing or is an admin
        if financing.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(
            financing, data=request.data, partial=True)

        try:
            if serializer.is_valid():
                serializer.save()
                response_data = {
                    "status": status.HTTP_200_OK,
                    "message": "Lease financing updated successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LeaseFinancingDeleteAPIView(APIView):
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Lease Financing Management"],
        operation_summary="Delete Lease Financing",
        operation_description="Delete the specified lease financing of the authenticated user.",
        responses={
            200: "Lease financing deleted successfully",
            403: "Forbidden",
            404: "Lease financing not found",
        }
    )
    def delete(self, request, financing_id, *args, **kwargs):
        # Retrieve the lease financing or raise a 404 error if not found
        try:
            financing = LeaseFinancing.objects.get(transaction_id=financing_id)
        except LeaseFinancing.DoesNotExist:
            raise Http404("Lease financing does not exist")

        # Check if the current user is the creator of the financing or is an admin
        if financing.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        # Delete the financing
        financing.delete()

        return Response({"status": status.HTTP_200_OK, "message": "Lease financing deleted successfully", "data": None}, status=status.HTTP_200_OK)


class LeaseFinancingStatusUpdateAPIView(APIView):
    permission_classes = [IsAdmin]

    def send_financing_update_notification(self, user, financing):
        status_messages = {
            'Pending': 'Your lease financing application is pending.',
            'Processing': 'Your lease financing application is being processed.',
            'Declined': 'Your lease financing application has been declined.',
            'Paid': 'Your lease financing has been paid.'
        }
        email_subject = 'Lease Financing Status Updated'
        email_body = render_to_string('email_templates/financing_update_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'financing_details': financing,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
            'status_message': status_messages.get(financing.status, 'Your lease financing application status has been updated.')
        })
        data = {
            'to_email': user.email,
            'email_subject': email_subject,
            'email_body': email_body
        }
        Util.send_email(data)

    @swagger_auto_schema(
        tags=["Lease Financing Management"],
        operation_summary="Update Lease Financing Status",
        operation_description="Update the status of a lease financing.",
        manual_parameters=[
            openapi.Parameter(
                name="financing_id",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="ID of the financing to be updated"
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_STRING, description="New status for the financing")
            }
        ),
        responses={
            200: openapi.Response(description="Financing status updated successfully"),
            400: openapi.Response(description="Bad request"),
            404: openapi.Response(description="Financing not found"),
            403: openapi.Response(description="Forbidden"),
        }
    )
    def patch(self, request, financing_id):
        try:
            financing = LeaseFinancing.objects.get(transaction_id=financing_id)
        except LeaseFinancing.DoesNotExist:
            return Response({"status": status.HTTP_404_NOT_FOUND, "message": "Financing not found"}, status=status.HTTP_404_NOT_FOUND)

        new_status = request.data.get('status')

        if new_status not in dict(LeaseFinancing.transaction_status_choices).keys():
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        previous_status = financing.status  # Store previous status for notification

        financing.status = new_status
        financing.save()

        # Send email notification to the user
        self.send_financing_update_notification(
            financing.created_by, financing)

        return Response({"status": status.HTTP_200_OK, "message": "Financing status updated successfully"}, status=status.HTTP_200_OK)
# ========================================================================================================================================#


# ==================================================CreateCorporateLoan======================================================
class CreateCorporateLoanAPIView(APIView):
    serializer_class = CorporateLoanSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAdminorCustomer]

    @staticmethod
    def send_loan_creation_notification(user, loan):
        email_subject = 'New Corporate Loan Application Created'
        email_body = render_to_string('email_templates/corporate_loan_creation_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'user_email': user.email,
            'loan_details': loan,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @staticmethod
    def send_followup_email(user):
        email_subject = 'Thank You for Your Corporate Loan Application'
        email_body = render_to_string('email_templates/followup_email.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': user.email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @swagger_auto_schema(
        tags=['Corporate Loan Management'],
        operation_summary="Create Corporate Loan",
        operation_description="Create a new corporate loan application.",
        request_body=CorporateLoanSerializer,
        responses={
            201: openapi.Response(description="Corporate loan application created successfully"),
            400: openapi.Response(description="Bad request"),
            500: openapi.Response(description="Internal server error"),
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        try:
            if serializer.is_valid():
                # Assuming you want to associate the loan application with the current user
                loan = serializer.save(created_by=request.user)

                # Get admin users
                admin_users = User.objects.filter(user_type='ADMIN')

                # Send notification email to admin users
                for admin_user in admin_users:
                    self.send_loan_creation_notification(admin_user, loan)

                # Send follow-up email to the user
                self.send_followup_email(request.user)

                response_data = {
                    "status": status.HTTP_201_CREATED,
                    "message": "Corporate loan application created successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=response_data["status"])
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=response_data["status"])
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=response_data["status"])


class ListCorporateLoansAPIView(APIView):
    serializer_class = GetCorporateLoanSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Corporate Loan Management"],
        operation_summary="List User's Corporate Loans",
        operation_description="Retrieve corporate loans created by the specified user.",
        responses={
            200: GetCorporateLoanSerializer(many=True),
            401: "Unauthorized",
            404: "User not found"
        }
    )
    def get(self, request, user_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)

        # Retrieve corporate loans created by the specified user
        loans = CorporateLoan.objects.filter(created_by=user)

        # Get the count of corporate loans
        loan_count = loans.count()

        serializer = self.serializer_class(loans, many=True)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Corporate loans retrieved successfully",
            "count": loan_count,
            "data": {
                "loans": serializer.data
            }
        }
        return Response(response_data, status=status.HTTP_200_OK)


class CorporateLoanDetailAPIView(APIView):
    serializer_class = GetCorporateLoanSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Corporate Loan Management"],
        operation_summary="Retrieve a Corporate Loan",
        operation_description="Retrieve details of a specific corporate loan created by the specified user.",
        responses={
            200: GetCorporateLoanSerializer(),
            401: "Unauthorized",
            403: "Forbidden",
            404: "Corporate loan not found"
        }
    )
    def get(self, request, user_id, loan_id, *args, **kwargs):
        # Retrieve the user or return 404 if not found
        user = get_object_or_404(User, id=user_id)
        # Retrieve the specific corporate loan created by the specified user
        loan = get_object_or_404(
            CorporateLoan, transaction_id=loan_id, created_by=user)

        serializer = self.serializer_class(loan)
        response_data = {
            "status": status.HTTP_200_OK,
            "message": "Corporate loan retrieved successfully",
            "data": serializer.data
        }
        return Response(response_data, status=status.HTTP_200_OK)


class UpdateCorporateLoanAPIView(APIView):
    serializer_class = CorporateLoanSerializer
    permission_classes = [IsAdminorCustomer]
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        tags=["Corporate Loan Management"],
        operation_summary="Update Corporate Loan",
        operation_description="Update the specified corporate loan of the authenticated user.",
        request_body=CorporateLoanSerializer,
        responses={
            200: openapi.Response(description="Corporate loan updated successfully"),
            400: openapi.Response(description="Bad request"),
            403: openapi.Response(description="Forbidden"),
            404: openapi.Response(description="Corporate loan not found"),
        }
    )
    def put(self, request, loan_id, *args, **kwargs):
        # Retrieve the corporate loan or return 404 if not found
        loan = get_object_or_404(
            CorporateLoan, transaction_id=loan_id)

        # Check if the current user is the creator of the loan or is an admin
        if loan.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        serializer = self.serializer_class(
            loan, data=request.data, partial=True)

        try:
            if serializer.is_valid():
                serializer.save()
                response_data = {
                    "status": status.HTTP_200_OK,
                    "message": "Corporate loan updated successfully",
                    "data": serializer.data
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                response_data = {
                    "status": status.HTTP_400_BAD_REQUEST,
                    "message": "Invalid data",
                    "data": serializer.errors
                }
                return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            response_data = {
                "status": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": str(e),
                "data": None
            }
            return Response(response_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteCorporateLoanAPIView(APIView):
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["Corporate Loan Management"],
        operation_summary="Delete Corporate Loan",
        operation_description="Delete the specified corporate loan of the authenticated user.",
        responses={
            200: "Corporate loan deleted successfully",
            403: "Forbidden",
            404: "Corporate loan not found",
        }
    )
    def delete(self, request, loan_id, *args, **kwargs):
        # Retrieve the corporate loan or raise a 404 error if not found
        try:
            loan = CorporateLoan.objects.get(transaction_id=loan_id)
        except CorporateLoan.DoesNotExist:
            raise Http404("Corporate loan does not exist")

        # Check if the current user is the creator of the loan or is an admin
        if loan.created_by != request.user and request.user.user_type != 'ADMIN':
            return Response({"status": status.HTTP_403_FORBIDDEN, "message": "Forbidden", "data": None}, status=status.HTTP_403_FORBIDDEN)

        # Delete the loan
        loan.delete()

        return Response({"status": status.HTTP_200_OK, "message": "Corporate loan deleted successfully", "data": None}, status=status.HTTP_200_OK)


class UpdateCorporateLoanStatusAPIView(APIView):
    permission_classes = [IsAdmin]

    def send_loan_update_notification(self, user, loan):
        status_messages = {
            'Pending': 'Your corporate loan application is pending.',
            'Processing': 'Your corporate loan application is being processed.',
            'Declined': 'Your corporate loan application has been declined.',
            'Paid': 'Your corporate loan has been paid.'
        }
        email_subject = 'Corporate Loan Status Updated'
        email_body = render_to_string('email_templates/corporate_loan_update_notification.html', {
            'user_full_name': f'{user.first_name} {user.last_name}',
            'loan_details': loan,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}",
            'status_message': status_messages.get(loan.status, 'Your corporate loan application status has been updated.')
        })
        data = {
            'to_email': user.email,
            'email_subject': email_subject,
            'email_body': email_body
        }
        Util.send_email(data)

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="Update Corporate Loan Status",
        operation_description="Update the status of a corporate loan.",
        manual_parameters=[
            openapi.Parameter(
                name="loan_id",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="ID of the loan to be updated"
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'status': openapi.Schema(type=openapi.TYPE_STRING, description="New status for the loan")
            }
        ),
        responses={
            200: openapi.Response(description="Loan status updated successfully"),
            400: openapi.Response(description="Bad request"),
            404: openapi.Response(description="Loan not found"),
            403: openapi.Response(description="Forbidden"),
        }
    )
    def patch(self, request, loan_id):
        try:
            loan = CorporateLoan.objects.get(transaction_id=loan_id)
        except CorporateLoan.DoesNotExist:
            return Response({"status": status.HTTP_404_NOT_FOUND, "message": "Loan not found"}, status=status.HTTP_404_NOT_FOUND)

        new_status = request.data.get('status')

        if new_status not in dict(CorporateLoan.transaction_status_choices).keys():
            return Response({"status": status.HTTP_400_BAD_REQUEST, "message": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)

        previous_status = loan.status  # Store previous status for notification

        loan.status = new_status
        loan.save()

        # Send email notification to the user
        self.send_loan_update_notification(loan.created_by, loan)

        return Response({"status": status.HTTP_200_OK, "message": "Loan status updated successfully"}, status=status.HTTP_200_OK)
# ===============================================================================================================================================#
