from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('resend-verification-code/', views.ResendVerificationCode.as_view(),
         name='resend_verification_code'),
    path('verify-email/', views.EmailVerificationAPIView.as_view(),
         name='verify-email'),
    path('signin/', views.LoginAPIView.as_view(), name='signin'),
    path('logout/', views.LogoutAPIView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('RequestPasswordResetEmail/', views.RequestPasswordResetEmail.as_view(),
         name="RequestPasswordResetEmail"),
    path('password-reset/<uidb64>/<token>/',
         views.PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', views.SetNewPasswordAPIView.as_view(),
         name='password-reset-complete'),

    # ============================static pages=========================

    path('products/', views.products, name='products'),
    path('login/', views.login, name='login'),
    path('forgetPassword/', views.forgetPassword, name='forgetPassword'),
    path('setnewpassword/', views.setnewpassword, name='setnewpassword'),
    path('verification/', views.verificationpage, name='verification'),
    path('setupprofile/', views.setupprofile, name='setupprofile'),
    path('signup/', views.signup, name='signup'),
    path('blog/', views.blog, name='blog'),
    path('contact/', views.contact, name='contact'),
    path('about/', views.about, name='about'),
    path('teams/', views.teams, name='teams'),
    path('faq/', views.faq, name='faq'),
    # service details
    path('TargetSavingsPlan/', views.ntsp, name='ntsp'),
    path('NobleserveNairaInvestment/', views.npn, name='npn'),
    path('LeaseFinancing/', views.lf, name='lf'),
    path('CorporateandCommercialLoans/', views.ccl, name='ccl'),
    path('Personal_Loans/', views.pl, name='pl'),

    # blog details
    path('blogdetails1/', views.blogdetails1, name='blogdetails1'),
    path('blogdetails2/', views.blogdetails2, name='blogdetails2'),
    path('blogdetails3/', views.blogdetails3, name='blogdetails3'),

    path('profile/update/', views.ProfileUpdateAPIView.as_view(),
         name='profile-update'),
    path('profile/detail/', views.ProfileDetailAPIView.as_view(),
         name='profile-detail'),
    path('email/change/', views.EmailChangeAPIView.as_view(), name='email_change'),
    path('password/change/', views.PasswordChangeAPIView.as_view(),
         name='password_change'),


    path('customerDashboard/', views.customerDashboard, name='customerDashboard'),
    path('staffDashboard/', views.staffDashboard, name='staffDashboard'),





]
