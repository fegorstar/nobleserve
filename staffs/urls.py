from django.urls import path
from . import views


urlpatterns = [
    path('personalLoans/', views.personalLoans, name='personalLoans'),
    path('targetSavings/', views.targetSavings, name='targetSavings'),
    path('LeaseFinancings/', views.LeaseFinancings, name='LeaseFinancings'),
    path('CorporateLoans/', views.CorporateLoans, name='CorporateLoans'),

    path('deactivate/<int:user_id>/',
         views.DeactivateAccountAPIView.as_view(), name='deactivate_account'),
    # ADMIN MANAGEMENT=======================================================
    path('list-registered-users/', views.ListRegisteredUsersAPIView.as_view(),
         name='list_registered_users'),
    path('allpersonal-loans/', views.AllPersonalLoanListAPIView.as_view(),
         name='all_personal_loans'),
    path('all/target-savings/', views.AllTargetSavingListAPIView.as_view(),
         name='all-target-savings'),
    path('all/lease-financing/', views.AllLeaseFinancingListAPIView.as_view(),
         name='all-lease-financing'),
    path('all/corporate-loans/', views.AllCorporateLoanListAPIView.as_view(),
         name='all-corporate-loans'),
    path('stats/', views.StatsAPIView.as_view(), name='stats'),


]
