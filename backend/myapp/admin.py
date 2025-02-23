from django.contrib import admin
from myapp.models import Role, UserRole

# Register your custom models
admin.site.register(Role)
admin.site.register(UserRole)
