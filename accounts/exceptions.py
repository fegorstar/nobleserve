from rest_framework.exceptions import APIException
from rest_framework import exceptions, status


class CustomException(exceptions.APIException):
    default_status_code = status.HTTP_400_BAD_REQUEST

    def __init__(self, detail=None, status_code=None):
        super().__init__(detail=None)
        if detail is not None:
            self.detail = {'error': detail}
        if status_code is not None:
            self.status_code = status_code
        else:
            self.status_code = self.default_status_code

    def get_full_details(self):
        # Include 'status' key with the actual status code
        return {'status_code': self.status_code, 'error': self.detail['error']}


class ValidationException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = 'Validation error'
    default_code = 'validation_error'

    def __init__(self, detail, field_errors=None):
        self.field_errors = field_errors
        super().__init__(detail)
