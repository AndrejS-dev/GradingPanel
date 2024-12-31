from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Student

# Register your models here.
class StudentAdmin(UserAdmin):
    # The forms to add and change user instances
    # If you've created custom forms for user creation and modification, you would specify them here
    # Otherwise, you can use the default ones from UserAdmin
    
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    # that reference specific fields on auth.User.
    list_display = ('uid', 'username', 'email', 'is_staff', 'is_banned', 'is_timeouted')
    fieldsets = UserAdmin.fieldsets + (
        (None, {'fields': ('passed_SDCA', 'passed_LTPI', 'passed_MTPI', 'passed_RSPS', 
                           'passed_S_BTC', 'passed_S_ETH', 'passed_S_ALT', 'passed_INTERVIEW', 'is_banned', 'timeout_until')}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (None, {'fields': ('passed_SDCA', 'passed_LTPI', 'passed_MTPI', 'passed_RSPS', 
                           'passed_S_BTC', 'passed_S_ETH', 'passed_S_ALT', 'passed_INTERVIEW', 'is_banned', 'timeout_until')}),
    )
admin.site.register(Student, StudentAdmin)
