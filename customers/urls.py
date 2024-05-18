from django.urls import path
from . import views


urlpatterns = [
    path('profile/update/', views.ProfileUpdateAPIView.as_view(),
         name='profile-update'),
    path('profile/detail/', views.ProfileDetailAPIView.as_view(),
         name='profile-detail'),
    path('email/change/', views.EmailChangeAPIView.as_view(), name='email_change'),
    path('password/change/', views.PasswordChangeAPIView.as_view(),
         name='password_change'),
    path('deactivate/<int:user_id>/',
         views.DeactivateAccountAPIView.as_view(), name='deactivate_account'),

    path('profile/', views.profile, name='profile'),
    path('personalloans/', views.personalloans, name='personalloans'),
    path('addpersonalloan/', views.addpersonalloan, name='addpersonalloan'),

    path('personal-loan/create/', views.PersonalLoanCreateAPIView.as_view(),
         name='personal_loan_create'),
    path('mypersonalloans/<int:user_id>/',
         views.UserPersonalLoanListAPIView.as_view(), name='mypersonalloans'),
    path('mypersonalloan/<int:user_id>/<str:loan_id>/',
         views.UserPersonalLoanDetailAPIView.as_view(), name='mypersonalloan-detail'),
    path('personal-loans/update/<str:loan_id>/',
         views.PersonalLoanUpdateAPIView.as_view(), name='personal_loan_update'),
    path('personal-loans/delete/<str:loan_id>/',
         views.PersonalLoanDeleteAPIView.as_view(), name='personal_loan_delete'),
    path('personal-loans/update-status/<str:loan_id>/',
         views.PersonalLoanStatusUpdateAPIView.as_view()),

    # ADMIN MANAGEMENT=======================================================
    path('list-registered-users/', views.ListRegisteredUsersAPIView.as_view(),
         name='list_registered_users'),
    path('allpersonal-loans/', views.AllPersonalLoanListAPIView.as_view(),
         name='all_personal_loans'),
    path('stats/', views.StatsAPIView.as_view(), name='stats'),
]
