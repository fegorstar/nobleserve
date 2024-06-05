from django.urls import path
from . import views

urlpatterns = [

    path('admin-dashboard/', views.dashboard, name='admin-dashboard'),
    path('admin-login/', views.adminlogin, name='admin-login'),
    path('customers/', views.customers, name='customers'),
    path('loanrequests/', views.loanrequests, name='loanrequests'),
    path('targetsavings/', views.targetsavings, name='targetsavings'),
    path('approvedloans/', views.approvedloans, name='approvedloans'),
    path('declinedloans/', views.declinedloans, name='declinedloans'),

]
