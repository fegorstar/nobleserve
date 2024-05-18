from rest_framework.permissions import BasePermission
from .exceptions import CustomException


class IsAdminorCustomer(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.is_verified
            and (request.user.user_type in ['ADMIN', 'CUSTOMER'])
        )


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.is_verified
            and (request.user.user_type in ['ADMIN'])
        )


class IsSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            raise CustomException(
                detail='You do not have permission to perform this action.')

        # Check if the user is a super admin
        if request.user.user_type == 'ADMIN' and request.user.is_superuser:
            return True

        raise CustomException(
            detail='You do not have permission to perform this action.')
