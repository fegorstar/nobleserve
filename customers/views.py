from django.conf import settings
from rest_framework.generics import ListAPIView
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from rest_framework import permissions
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Profile
from .serializers import ProfileUpdateSerializer, ProfileSerializer, EmailChangeSerializer, PasswordChangeSerializer, PersonalLoanSerializer, GetPersonalLoanSerializer
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
from .models import PersonalLoan
from accounts.utils import Util
from django.utils.translation import gettext_lazy as _
from accounts.exceptions import CustomException
from accounts.models import User
# ====================================ProfileUpdateAPIView======================================


class ProfileUpdateAPIView(APIView):
    serializer_class = ProfileUpdateSerializer
    parser_classes = [MultiPartParser, FormParser]
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["User Profile Management"],
        operation_summary="Update Profile",
        operation_description="Update the profile details.",
        request_body=ProfileUpdateSerializer,
        responses={
            200: openapi.Response(description="Profile updated successfully"),
            400: "Bad Request",
            404: "Profile not found"
        }
    )
    def put(self, request, *args, **kwargs):
        try:
            # Check if user is authenticated
            if not request.user.is_authenticated:
                raise CustomException(detail="Authentication credentials were not provided.",
                                      status_code=status.HTTP_401_UNAUTHORIZED)

            # Fetch the profile based on the authenticated user
            profile = Profile.objects.get(user=request.user)
            serializer = self.serializer_class(
                profile, data=request.data, context={'request': request})

            if serializer.is_valid():
                serializer.save()
                return Response({"status": status.HTTP_200_OK, "message": "Profile updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)

            return Response({"status": status.HTTP_400_BAD_REQUEST, "error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Profile.DoesNotExist:
            raise CustomException(detail="Profile not found",
                                  status_code=status.HTTP_404_NOT_FOUND)

        except CustomException as e:
            return Response({"error": e.detail['error']}, status=e.status_code)
# ======================================================================================================#


# =======================================ProfileDetailAPIView=================================================

class ProfileDetailAPIView(APIView):
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["User Profile Management"],
        operation_summary="Get Profile Details",
        operation_description="Get the profile details of the authenticated user.",
        responses={
            200: openapi.Response(description="Profile details retrieved successfully"),
            401: "Unauthorized"
        }
    )
    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            profile = Profile.objects.get(user=user)
            # Assuming you have a serializer for profile details
            serializer = ProfileSerializer(profile)
            # Include user ID within the "user" object
            user_data = {
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "user_type": user.user_type,
                "is_active": user.is_active
            }
            # Merge user data and profile data
            profile_data = {
                **user_data,
                "profile_picture": serializer.data.get("profile_picture"),
                "state": serializer.data.get("state"),
                "city": serializer.data.get("city"),
                "country": serializer.data.get("country"),
                "address": serializer.data.get("address"),
                "sex": serializer.data.get("sex"),
                "dob": serializer.data.get("dob"),
                "phone_number": serializer.data.get("phone_number"),
                "created_at": serializer.data.get("created_at"),
                "updated_at": serializer.data.get("updated_at")
            }
            # Create the response data
            response_data = {
                "status": status.HTTP_200_OK,
                "profile": profile_data
            }
            return Response(response_data, status=status.HTTP_200_OK)

        except Profile.DoesNotExist:
            raise CustomException(detail="Profile not found",
                                  status_code=status.HTTP_404_NOT_FOUND)

        except CustomException as e:
            return Response({"error": e.detail['error']}, status=e.status_code)
# =======================================================================================================#


# ===================================EmailChangeAPIView======================================================


class EmailChangeAPIView(GenericAPIView):
    serializer_class = EmailChangeSerializer
    permission_classes = [IsAdminorCustomer]

    @staticmethod
    def send_verification_email(request, user, new_email):
        email_subject = 'Email Change Confirmation'
        email_template = 'email_templates/email_change_notification.html'
        email_recipient = new_email

        org_name = 'Nobleserve Finance'
        support_email = 'cx@nobleservefinance.com'

        email_context = {
            'user': user,
            'new_email': new_email,
            'organization_name': org_name,
            'support_email': support_email,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        }

        email_data = {
            'email_body': render_to_string(email_template, email_context),
            'to_email': email_recipient,
            'email_subject': email_subject,
        }

        Util.send_email(email_data)

    @swagger_auto_schema(
        tags=["User Profile Management"],
        operation_summary="Change User Email",
        operation_description="Change the email address of the current authenticated user.",
        request_body=EmailChangeSerializer,
        responses={
            200: openapi.Response(description="Email updated successfully"),
            400: openapi.Response(description="Bad request"),
            403: openapi.Response(description="Forbidden"),
        }
    )
    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = request.user

        try:
            # Authenticate the user with the current password
            auth_user = authenticate(email=user.email, password=password)
            if not auth_user:
                return Response({'error': 'Invalid password'}, status=status.HTTP_403_FORBIDDEN)

            # Validate the new email format
            validate_email(new_email)

            # Check if the new email is already in use
            if User.objects.exclude(pk=user.pk).filter(email=new_email).exists():
                return Response({'error': 'Email address is already in use. Please choose a different email address.'}, status=status.HTTP_400_BAD_REQUEST)

            # Update the user's email
            user.email = new_email
            user.save()

            # Send email notification
            self.send_verification_email(request, user, new_email)

            return Response({'status': status.HTTP_200_OK, 'message': _('Email updated successfully'), 'data': serializer.data}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
# =================================================================================================================#

# ================================================PasswordChangeAPIView==============================


class PasswordChangeAPIView(GenericAPIView):
    serializer_class = PasswordChangeSerializer
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=['User Profile Management'],
        operation_summary="Change User Password",
        operation_description="Change the password of the authenticated user.",
        request_body=PasswordChangeSerializer,
        responses={
            200: openapi.Response(description="Password updated successfully"),
            400: openapi.Response(description="Bad request"),
            403: openapi.Response(description="Forbidden"),
        }
    )
    def patch(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        current_password = serializer.validated_data['current_password']
        new_password = serializer.validated_data['new_password']
        user = request.user

        try:
            # Authenticate the user with the current password
            auth_user = authenticate(
                email=user.email, password=current_password)
            if not auth_user:
                return Response({'error': 'Invalid current password'}, status=status.HTTP_403_FORBIDDEN)

            # Updating the user's password
            user.set_password(new_password)
            user.save()

            return Response({'success': True, 'message': 'Password updated successfully'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)

# =====================================================================================================#

# ============================================DeactivateAccountAPIView====================================


class DeactivateAccountAPIView(APIView):
    permission_classes = [IsAdminorCustomer]

    @swagger_auto_schema(
        tags=["User Profile Management"],
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
            'user_full_name': f'{user.first_name} {user.last_name}',
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


class StatsAPIView(APIView):
    permission_classes = [IsAdmin]

    @swagger_auto_schema(
        tags=["Loan Management"],
        operation_summary="Get Statistics",
        operation_description="Retrieve statistics about the system, including customer count and personal loan count.",
        responses={
            200: openapi.Response(
                description="Statistics retrieved successfully",
                examples={
                    'application/json': {
                        "status": status.HTTP_200_OK,
                        "message": "Statistics retrieved successfully",
                        "data": {
                            "customer_count": 100,
                            "personal_loan_count": 50
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

        data = {
            "customer_count": customer_count,
            "personal_loan_count": personal_loan_count
        }

        response = {
            "status": status.HTTP_200_OK,
            "message": "Statistics retrieved successfully",
            "data": data
        }

        return Response(response, status=status.HTTP_200_OK)

# STATIC PAGES


def profile(request):
    return render(request, 'customers/profile.html')


def personalloans(request):
    return render(request, 'customers/personalloans.html')


def addpersonalloan(request):
    return render(request, 'customers/addpersonalloan.html')
