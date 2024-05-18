from django.contrib import admin
from .models import User
from django.utils.html import format_html


# Register your models here.
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'first_name', 'last_name', 'email',
                    'user_type', 'is_active', 'last_login', 'is_verified')
    list_display_links = ('id', 'email', 'first_name', 'last_name')
    readonly_fields = ('last_login', 'created_at')
    ordering = ('-created_at',)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


admin.site.register(User, CustomUserAdmin)
