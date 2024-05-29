from .models import PersonalLoan, TargetSaving, LeaseFinancing, CorporateLoan
from django.contrib import admin
from .models import Profile
from django.utils.html import format_html


class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user_email', 'state', 'city',
                    'phone_number', 'created_at', 'updated_at')
    list_display_links = ('user_email',)
    readonly_fields = ('created_at', 'updated_at')

    def user_email(self, obj):
        return obj.user.email

    def subjects_list(self, obj):
        return ', '.join(obj.subject) if obj.subject else ''

    user_email.short_description = 'User Email'
    subjects_list.short_description = 'Subjects'


class CustomPersonalLoan(admin.ModelAdmin):
    list_display = ('transaction_id', 'created_by', 'sex',
                    'dob', 'amount', 'status', 'created_at')
    ordering = ('-created_at',)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


class CustomTargetSaving(admin.ModelAdmin):
    list_display = ('transaction_id', 'created_by',
                    'amount', 'status', 'created_at')
    ordering = ('-created_at',)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


class CustomLeaseFinancing(admin.ModelAdmin):
    list_display = ('created_by', 'equipment_type', 'equipment_amount', 'has_funding',
                    'acquisition_timeline', 'has_documents', 'repayment_duration', 'location')
    ordering = ('-id',)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


class CustomCorporateLoan(admin.ModelAdmin):
    list_display = ('created_by', 'business_age', 'industry', 'loan_purpose',
                    'loan_amount', 'has_documents', 'repayment_duration')
    ordering = ('-id',)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


admin.site.register(TargetSaving, CustomTargetSaving)
admin.site.register(CorporateLoan, CustomCorporateLoan)
admin.site.register(LeaseFinancing, CustomLeaseFinancing)
admin.site.register(PersonalLoan, CustomPersonalLoan)
admin.site.register(Profile, ProfileAdmin)
