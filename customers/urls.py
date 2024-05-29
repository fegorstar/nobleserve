from django.urls import path
from . import views

urlpatterns = [

    # static pages- CUSTOMERS
    path('profile/', views.profile, name='profile'),
    path('personalloans/', views.personalloans, name='personalloans'),
    path('myTargetSavings/', views.myTargetSavings, name='myTargetSavings'),
    path('myleaseFinancings/', views.myleaseFinancings, name='myleaseFinancings'),
    path('mycorporateLoans/', views.mycorporateLoans, name='mycorporateLoans'),


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


    path('target-saving/create/', views.TargetSavingCreateAPIView.as_view(),
         name='create_target_saving'),
    path('target-savings/<int:user_id>/',
         views.UserTargetSavingListAPIView.as_view(), name='user_target_savings'),
    path('target-saving/<int:user_id>/<str:saving_id>/',
         views.TargetSavingDetailAPIView.as_view(), name='target_saving_detail'),
    path('target-saving/update/<str:saving_id>/',
         views.TargetSavingUpdateAPIView.as_view(), name='target_saving_update'),
    path('target-saving/delete/<str:saving_id>/',
         views.TargetSavingDeleteAPIView.as_view(), name='target_saving_delete'),
    path('target-saving/status-update/<str:saving_id>/',
         views.TargetSavingStatusUpdateAPIView.as_view(), name='target_saving_status_update'),


    path('lease-financing/create/', views.LeaseFinancingCreateAPIView.as_view(),
         name='lease_financing_create'),
    path('lease-financings/<int:user_id>/',
         views.LeaseFinancingListAPIView.as_view(), name='lease_financing_list'),
    path('lease-financing/<int:user_id>/<str:financing_id>/',
         views.LeaseFinancingDetailAPIView.as_view(), name='lease_financing_detail'),
    path('lease-financing/update/<str:financing_id>/',
         views.LeaseFinancingUpdateAPIView.as_view(), name='lease_financing_update'),
    path('lease-financing/delete/<str:financing_id>/',
         views.LeaseFinancingDeleteAPIView.as_view(), name='lease_financing_delete'),
    path('lease-financing/status-update/<str:financing_id>/',
         views.LeaseFinancingStatusUpdateAPIView.as_view(), name='lease_financing_status_update'),


    path('corporate-loans/create/', views.CreateCorporateLoanAPIView.as_view(),
         name='create-corporate-loan'),
    path('corporate-loans/<int:user_id>/',
         views.ListCorporateLoansAPIView.as_view(), name='list-corporate-loans'),
    path('corporate-loan/<int:user_id>/<str:loan_id>/',
         views.CorporateLoanDetailAPIView.as_view(), name='corporate-loan-detail'),
    path('corporate-loan/update/<str:loan_id>/',
         views.UpdateCorporateLoanAPIView.as_view(), name='update-corporate-loan'),
    path('corporate-loan/delete/<str:loan_id>/',
         views.DeleteCorporateLoanAPIView.as_view(), name='delete-corporate-loan'),
    path('corporate-loan/status-update/<str:loan_id>/',
         views.UpdateCorporateLoanStatusAPIView.as_view(), name='update-corporate-loan-status'),



]
