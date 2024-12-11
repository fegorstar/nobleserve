from django.contrib.auth.models import User
import shortuuid
from django.db import models
from django.utils.translation import gettext_lazy as _
from accounts.models import User
from django.contrib.postgres.fields import ArrayField
from shortuuid.django_fields import ShortUUIDField
from django.db.models.fields.related import ForeignKey, OneToOneField


class Profile(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, primary_key=True)
    profile_picture = models.ImageField(
        upload_to='users/profile_pictures', blank=True, null=True)
    address = models.TextField(blank=True, null=True, default="")
    country = models.CharField(max_length=250, default="")
    sex = models.CharField(max_length=250, default="")
    dob = models.CharField(max_length=250, default="")
    state = models.CharField(max_length=250, default="")
    city = models.CharField(max_length=250, default="")
    phone_number = models.CharField(max_length=11)
    created_at = models.DateTimeField(
        auto_now_add=True, verbose_name=_('Created At'))
    updated_at = models.DateTimeField(
        auto_now=True, verbose_name=_('Updated At'))

    def __str__(self):
        return self.user.email


class PersonalLoan(models.Model):

    # jobstatus- value and key
    transaction_status_choices = (
        ('Pending', 'Pending'),
        ('Processing', 'Processing'),
        ('Declined', 'Declined'),
        ('Paid', 'Paid'),
    )

    # gender
    sex_choices = (
        ('Male', 'Male'),
        ('Female', 'Female'),
    )

    # in django we dont need to define the primary key it happens automatically behind the scene
    transaction_id = ShortUUIDField(
        length=12,
        max_length=40,
        prefix="NBL_",
        alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-",
    )

    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE)  # customer name
    sex = models.CharField(choices=sex_choices, max_length=100)
    dob = models.DateField(max_length=8)
    address = models.CharField(max_length=250)
    occupation = models.CharField(max_length=100)
    purpose_of_loan = models.TextField(max_length=100)
    status = models.CharField(
        choices=transaction_status_choices, max_length=100, default='Pending')  # Default status set to 'Pending'
    amount = models.CharField(max_length=10)
    duration = models.DateField(max_length=8)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        # solves the issue with nontype
        return self.sex


# TargetSaving model
class TargetSaving(models.Model):
    transaction_status_choices = (
        ('Pending', 'Pending'),
        ('Processing', 'Processing'),
        ('Declined', 'Declined'),
        ('Paid', 'Paid'),
    )

    transaction_id = ShortUUIDField(
        length=12,
        max_length=40,
        prefix="NBL_",
        alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-",
    )

    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE)  # customer name
    amount = models.CharField(max_length=10)
    start_save = models.DateField()
    save_by = models.DateField()
    status = models.CharField(
        choices=transaction_status_choices, max_length=100, default='Pending')

    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.created_by.email if self.created_by else ''

class LeaseFinancing(models.Model):
    YES = 'Yes'
    NO = 'No'

    BOOLEAN_CHOICES = [
        (YES, 'Yes'),
        (NO, 'No'),
    ]

    transaction_status_choices = (
        ('Pending', 'Pending'),
        ('Processing', 'Processing'),
        ('Declined', 'Declined'),
        ('Paid', 'Paid'),
    )

    transaction_id = ShortUUIDField(
        length=12,
        max_length=40,
        prefix="NBL_",
        alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-",
    )
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)  # customer name
    status = models.CharField(choices=transaction_status_choices, max_length=100, default='Pending')
    equipment_type = models.CharField(max_length=255)
    equipment_amount = models.DecimalField(max_digits=12, decimal_places=2)
    has_funding = models.CharField(choices=BOOLEAN_CHOICES, max_length=3)
    acquisition_timeline = models.CharField(max_length=100)
    has_documents = models.CharField(choices=BOOLEAN_CHOICES, max_length=3)
    document_link = models.URLField(max_length=200, blank=True)
    repayment_duration = models.CharField(max_length=100)
    location = models.CharField(max_length=255)

    def __str__(self):
        return f"Lease Financing - {self.id}"

   

class CorporateLoan(models.Model):
    YES = 'Yes'
    NO = 'No'

    BOOLEAN_CHOICES = [
        (YES, 'Yes'),
        (NO, 'No'),
    ]

    transaction_status_choices = (
        ('Pending', 'Pending'),
        ('Processing', 'Processing'),
        ('Declined', 'Declined'),
        ('Paid', 'Paid'),
    )

    transaction_id = ShortUUIDField(
        length=12,
        max_length=40,
        prefix="NBL_",
        alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-",
    )
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)  # customer name
    status = models.CharField(choices=transaction_status_choices, max_length=100, default='Pending')
    business_age = models.PositiveIntegerField()
    industry = models.CharField(max_length=255)
    loan_purpose = models.TextField()
    loan_amount = models.DecimalField(max_digits=12, decimal_places=2)
    has_documents = models.CharField(choices=BOOLEAN_CHOICES, max_length=3)
    document_link = models.URLField(max_length=200, blank=True)
    repayment_duration = models.CharField(max_length=100)

    def __str__(self):
        return f"Corporate Loan - {self.id}"

   