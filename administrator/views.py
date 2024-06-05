from django.conf import settings
from rest_framework.generics import ListAPIView
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from rest_framework import permissions
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

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
# ====================================ProfileUpdateAPIView======================================


def dashboard(request):
    return render(request, 'administrator/pages/dashboard.html')


def adminlogin(request):
    return render(request, 'administrator/pages/login.html')


def customers(request):
    return render(request, 'administrator/pages/customers.html')


def loanrequests(request):
    return render(request, 'administrator/pages/loanrequests.html')


def approvedloans(request):
    return render(request, 'administrator/pages/approvedloans.html')


def declinedloans(request):
    return render(request, 'administrator/pages/declinedloans.html')


def targetsavings(request):
    return render(request, 'administrator/pages/targetsavings.html')