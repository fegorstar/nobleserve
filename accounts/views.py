from .permissions import IsAdminorCustomer, IsAdmin
from rest_framework.decorators import permission_classes
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from drf_yasg import openapi
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from rest_framework import permissions
from rest_framework_simplejwt.tokens import TokenError
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import check_password
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response
from .serializers import RegisterSerializer, VerificationRequestSerializer, LoginSerializer, VerificationRequestSerializer, LogoutSerializer, ResendVerificationCodeSerializer, ResetPasswordEmailRequestSerializer, SetNewPasswordSerializer
from .models import User
from customers.serializers import ProfileSerializer
from customers.models import Profile
from .utils import Util, generate_verification_code
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from django.template.loader import render_to_string
from accounts.exceptions import CustomException, ValidationException
from rest_framework import status
from rest_framework import generics, status, views, permissions
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from decouple import config, Csv
from django.http import HttpResponsePermanentRedirect
from django.contrib.auth.models import update_last_login
from rest_framework import generics
from django.shortcuts import get_object_or_404, redirect, render


# ===================================================STATIC PAGES LOGICS======================================
class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [config('APP_SCHEME'), 'http', 'https']


# =======================RegisterView====================================================
class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    @staticmethod
    def send_notification_email(user, verification_code):
        organization_email = 'abighe-simon.pius@datasphir.com'
        organization_name = 'Nobleserve Finance'
        user_full_name = f'{user.first_name} {user.last_name}'
        user_email = user.email

        email_subject = 'New User Registration'
        email_body = render_to_string('email_templates/new_user_notification.html', {
            'organization_name': organization_name,
            'user_full_name': user_full_name,
            'user_email': user_email,
            # Include verification code in the email
            'verification_code': verification_code,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"

        })
        email_data = {
            'email_subject': email_subject,
            'to_email': organization_email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="User Registration",
        operation_description="Register a new user and send a verification code to their email. Also, notify the organization about the new registration.",
        responses={
            201: "User registered successfully. Check your email to Verify your Account.",
            400: "Bad request. Check the request payload.",
        }
    )
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        # Check if user already exists
        if User.objects.filter(email=email).exists():
            error_message = "User with this email address already exists."
            return Response({'status_code': status.HTTP_400_BAD_REQUEST, 'error': error_message}, status=status.HTTP_400_BAD_REQUEST)

        # Save the validated data to the database
        user = serializer.save()

        # Generate verification code
        verification_code = generate_verification_code()

        # Save verification code and creation time to the user instance
        token = RefreshToken.for_user(user).access_token
        user.verification_code = verification_code
        user.verification_code_created_at = timezone.now()  # Set current datetime
        user.save()

        # Generate verification link with verification code
        current_site = get_current_site(request).domain
        verification_link = 'http://' + current_site + \
            '/auth/verification/?verification_code=' + str(verification_code)

        # Send verification email to the user
        email_subject = 'Account Verification'
        email_body = render_to_string('email_templates/email_verification.html', {
            'verification_code': verification_code,
            'user_full_name': user.first_name,
            # Include verification link in the email
            'verification_link': verification_link,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        })
        email_data = {
            'email_subject': email_subject,
            'to_email': email,
            'email_body': email_body,
        }
        Util.send_email(email_data)

        # Send notification email to the organization
        self.send_notification_email(user, verification_code)

        # Prepare response data
        response_data = {
            'status': status.HTTP_201_CREATED,
            'message': 'User registered successfully. Check your email to verify your account.',
            'data': {
                'full_name': f'{user.first_name} {user.last_name}',
                'email': email,
            }
        }

        # Return success response
        return Response(response_data, status=status.HTTP_201_CREATED)
# ========================================================================================================


# ========================ResendVerificationCode======================================================
class ResendVerificationCode(APIView):
    serializer_class = ResendVerificationCodeSerializer

    @staticmethod
    def send_verification_email(request, user, verification_code):
        current_site = get_current_site(request)
        domain = current_site.domain
        verification_link = f"http://{domain}/auth/verification/?verification_code={verification_code}"
        email_subject = 'Resend Verification Code'
        email_body = render_to_string(
            'email_templates/resend_verification_code.html',
            {'user': user, 'verification_code': verification_code,
             'verification_link': verification_link,
             'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"

             })
        email_data = {'email_subject': email_subject,
                      'to_email': user.email, 'email_body': email_body}
        Util.send_email(email_data)

    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="Resend Verification Code",
        operation_description="Resend the verification code to the user's email.",
        request_body=ResendVerificationCodeSerializer,
        responses={
            200: "Verification code resent successfully.",
            400: "Bad request. Check the request payload.",
            404: "User not found."
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)

            # Generate new verification code and update user instance
            verification_code = generate_verification_code()
            user.verification_code = verification_code
            user.verification_code_created_at = timezone.now()
            user.save()

            # Send verification email to the user
            self.send_verification_email(request, user, verification_code)

            # Return success response
            response_data = {
                'status_code': status.HTTP_200_OK,
                'message': 'Verification code resent successfully.',
            }
            return Response(response_data, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
# ===============================================================================================#


# =========================EmailVerificationAPIView======================================
class EmailVerificationAPIView(APIView):
    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="Email Verification",
        operation_description="Verify the user's email address using the verification code.",
        request_body=VerificationRequestSerializer,
        responses={
            200: "Email verified successfully.",
            400: "Bad request. Check the provided verification code.",
        }
    )
    def post(self, request):
        verification_code = request.data.get('verification_code')

        if not verification_code:
            return Response({'error': 'Verification code not provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(verification_code=verification_code)
        except User.DoesNotExist:
            return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_verified:
            return Response({'error': 'Email already verified'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if verification code is expired
        # Assuming verification code expires after 5 minutes
        expiration_timeframe = timezone.now() - timezone.timedelta(minutes=5)
        if user.verification_code_created_at < expiration_timeframe:
            return Response({'error': 'Verification code expired. Request for a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        # Verification successful, update user status
        user.is_verified = True
        user.save()

        # Send verification success email to user
        email_subject = _('Email Verification Success')
        email_body = render_to_string(
            'email_templates/email_verification_success.html', {'user': user, 'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"})
        email_data = {'email_subject': email_subject,
                      'to_email': user.email, 'email_body': email_body}
        Util.send_email(email_data)

        response_data = {
            'status_code': status.HTTP_200_OK,
            'message': 'Email verified successfully',
            'data': {'user_id': user.id}  # Include any relevant data here
        }

        return Response(response_data, status=status.HTTP_200_OK)


# ===============================================================================================#

# =========================================================LoginAPIView===================================


class LoginAPIView(APIView):
    serializer_class = LoginSerializer

    def send_verification_email(self, user, email, OrgName, support_email, verification_code):
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(self.request).domain
        verification_link = 'http://' + current_site + \
            '/verify-email/?verification_code=' + str(verification_code)
        context = {
            'user': user,
            'organization_name': OrgName,
            'support_email': support_email,
            'verification_code': verification_code,
            'verification_link': verification_link,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        }
        email_body = render_to_string(
            'email_templates/email_activation_reminder.html', context)
        data = {
            'email_body': email_body,
            'to_email': email,
            'email_subject': 'Verify your email to Activate your Account'
        }
        Util.send_email(data)
        print(f"Verification email sent to {email} for organization {OrgName}")

    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="User Login",
        operation_description="Login with email and password. If the user is not verified and the verification code is not expired, a new verification code will be generated and sent to the user's email.",
        request_body=LoginSerializer,
        responses={
            200: "Login successful.",
            400: "Bad request. Check the request payload.",
            401: "Unauthorized. User not verified or invalid login credentials."
        }
    )
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = User.objects.get(email=email)

            if password and check_password(password, user.password):
                if not user.is_active:
                    raise CustomException(detail=_(
                        'Account disabled, contact admin!'), status_code=status.HTTP_401_UNAUTHORIZED)

                if not user.is_verified:
                    if user.verification_code_created_at:
                        expiration_timeframe = timezone.now() - timezone.timedelta(minutes=15)
                        if user.verification_code_created_at > expiration_timeframe:
                            verification_code = generate_verification_code()
                            user.verification_code = verification_code
                            user.verification_code_created_at = timezone.now()
                            user.save()

                            support_email = 'cx@nobleservefinance.com'  # Updated support email
                            OrgName = 'Nobleserve Finance'  # Updated organization name
                            self.send_verification_email(
                                user, email, OrgName, support_email, verification_code)
                            raise CustomException(detail=_(
                                'Email is not verified. An Email has been Sent to you to Verify your Account!'), status_code=status.HTTP_401_UNAUTHORIZED)
                        else:
                            raise CustomException(detail=_(
                                'Verification code has expired. Please request a new one.'), status_code=status.HTTP_401_UNAUTHORIZED)
                    else:
                        raise CustomException(detail=_(
                            'Email is not verified. Please verify your email first.'), status_code=status.HTTP_401_UNAUTHORIZED)

                # Update user's last login
                update_last_login(None, user)

                refresh = RefreshToken.for_user(user)
                access_token = str(refresh.access_token)
                refresh_token = str(refresh)

                # Fetch user profile
                profile = Profile.objects.get(user=user)
                profile_serializer = ProfileSerializer(profile)

                response_data = {
                    'status_code': status.HTTP_200_OK,
                    'message': _('User logged in successfully'),
                    'data': {
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'email': user.email,
                        'user_type': user.user_type,  # Include user type
                        # Include profile image
                        'profile_picture': profile_serializer.data.get("profile_picture"),
                        'country': profile_serializer.data.get("country"),
                        'tokens': {
                            'refresh': refresh_token,
                            'access': access_token,
                        },
                    }
                }
                return Response(response_data, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            pass

        raise CustomException(detail=_(
            'Invalid login credentials'), status_code=status.HTTP_401_UNAUTHORIZED)
# ===============================================================================================#


# ==========================LogoutAPIView==================================================
class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="User Logout",
        operation_description="Logout the user and invalidate their tokens.",
        request_body=LogoutSerializer,
        responses={
            200: "Logout successful.",
            401: "Unauthorized. User not authenticated.",
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # Add a custom message to the response
        response_data = {'error': 'Successfully logged out.'}
        return Response(response_data, status=status.HTTP_200_OK)
# ===============================================================================================#


# ===============================RequestPasswordResetEmail========================================
class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="Request Password Reset Email",
        operation_description="Send an email to reset the password associated with the provided email address.",
        request_body=ResetPasswordEmailRequestSerializer,
        responses={
            200: "Email sent successfully.",
            400: "Bad request. Check the request payload.",
            404: "User not found."
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')

        try:
            # Your logic to retrieve the user goes here
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = get_current_site(request=request).domain
        # Change this to your actual endpoint for setting a new password
        relative_link = "/auth/setnewpassword/"
        reset_url = f"http://{current_site}{relative_link}?token={token}&uidb64={uidb64}"

        # Define organization name and support email
        org_name = 'Nobleserve finance'
        support_email = 'cx@nobleservefinance.com'

        # Render the email template with the reset URL
        email_subject = 'Reset your password'
        email_body = render_to_string('email_templates/reset_password_email.html', {
            'reset_url': reset_url,
            'user': user,
            'organization_name': org_name,
            'support_email': support_email,
            'absolute_static_url': f"{settings.BASE_URL}{settings.STATIC_URL}"
        })

        # Send the email using Util class
        email_data = {
            'email_subject': email_subject,
            'to_email': email,
            'email_body': email_body,
        }
        try:
            Util.send_email(email_data)
        except Exception as e:
            return Response({'error': f'Failed to send email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'success': 'We have sent you a link to reset your password. Check your email.'}, status=status.HTTP_200_OK)
# ==============================================================================================================================================#


# ================================CHECK TOKEN IF VALID TO CHANGE PASSWORD====================================
class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="Check Token Validity for Password Reset",
        operation_description="Check if the provided token is valid for resetting the password.",
        manual_parameters=[
            openapi.Parameter(
                name="uidb64",
                in_=openapi.IN_PATH,
                required=True,
                type=openapi.TYPE_STRING,
                description="The user ID encoded in base64."
            ),
            openapi.Parameter(
                name="token",
                in_=openapi.IN_PATH,
                required=True,
                type=openapi.TYPE_STRING,
                description="The token sent to the user for password reset."
            ),
            openapi.Parameter(
                name="redirect_url",
                in_=openapi.IN_QUERY,
                required=False,
                type=openapi.TYPE_STRING,
                description="Optional redirect URL with query parameters indicating token validity."
            ),
        ],
        responses={
            200: "Token is valid.",
            400: "Bad request. The token is not valid.",
        }
    )
    def get(self, request, uidb64, token):
        redirect_url = request.GET.get('redirect_url', '')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return self.invalid_token_response(redirect_url)

            # If the token is valid, proceed with your logic here
            return Response({'message': 'Token is valid'}, status=status.HTTP_200_OK)

        except (DjangoUnicodeDecodeError, User.DoesNotExist):
            return self.invalid_token_response(redirect_url)

    def invalid_token_response(self, redirect_url):
        if redirect_url:
            # Append query parameters to the redirect URL
            redirect_url += '?token_valid=False'
        else:
            redirect_url = settings.BASE_URL + '?token_valid=False'

        return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_400_BAD_REQUEST)
# ==================================END OF CHECK TOKEN IF VALID TO CHANGE PASSWORD========================================


# ==================SetNewPasswordAPIView======================================
class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    @swagger_auto_schema(
        tags=["Authentication"],
        operation_summary="Set New Password",
        operation_description="Set a new password for the user using the provided reset token and user ID.",
        request_body=SetNewPasswordSerializer,
        responses={
            200: "Password updated successfully.",
            400: "Bad request. Check the request payload.",
            401: "Unauthorized. The reset link is invalid.",
        }
    )
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        token = serializer.validated_data.get('token')
        uidb64 = serializer.validated_data.get('uidb64')

        try:
            # Decoding uidb64 within the correct schema context
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'The reset link is invalid'}, status=status.HTTP_401_UNAUTHORIZED)

            password = serializer.validated_data.get('password')

            # Your remaining logic here - updating the password
            user.set_password(password)
            user.save()

            return Response({'success': True, 'message': 'Password updated successfully'}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
# ====================================================================================================#


# ========================================ALL STATIC PAGES=============================
# homepage
def home(request):
    return render(request, 'pages/home.html')

# register


def signup(request):
    return render(request, 'accounts/register.html')


# login
def login(request):
    return render(request, 'accounts/login.html')


def forgetPassword(request):
    return render(request, 'accounts/forgotPassword.html')


def setnewpassword(request):
    return render(request, 'accounts/setnewpassword.html')


def verificationpage(request):
    return render(request, 'accounts/verify-email.html')


def setupprofile(request):
    return render(request, 'accounts/setupprofile.html')

# # Loan


def products(request):
    return render(request, 'pages/products.html')


# About
def about(request):
    return render(request, 'pages/about.html')


# Contact
def contact(request):
    return render(request, 'pages/contact.html')

# faq


def faq(request):
    return render(request, 'pages/faq.html')

# BLog


def blog(request):
    return render(request, 'pages/blog.html')

# blog Details


def blogdetails1(request):
    return render(request, 'pages/blogdetails/blogpost1.html')


def blogdetails2(request):
    return render(request, 'pages/blogdetails/blogpost2.html')


def blogdetails3(request):
    return render(request, 'pages/blogdetails/blogpost3.html')

# services details page


def ntsp(request):
    return render(request, 'pages/services/ntsp.html')


def npn(request):
    return render(request, 'pages/services/npn.html')


def lf(request):
    return render(request, 'pages/services/leasefinancing.html')


def ccl(request):
    return render(request, 'pages/services/ccl.html')


def pl(request):
    return render(request, 'pages/services/personalloans.html')


def teams(request):
    return render(request, 'pages/teams.html')


# Customer Dashboard
def customerDashboard(request):
    return render(request, 'accounts/custDashboard.html')

# Staff Dashboard


def staffDashboard(request):
    return render(request, 'accounts/staffDashboard.html',)


def targetSavings(request):
    return render(request, 'staffs/target_savings.html')


def personalLoans(request):
    return render(request, 'staffs/personalLoans.html')


def addpersonalloan(request):
    return render(request, 'staffs/addpersonalloan.html')
# ===============================================================end of static pages======================================
