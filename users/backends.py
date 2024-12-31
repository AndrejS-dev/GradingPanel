from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()

class UIDBackend(ModelBackend):
    def authenticate(self, request, uid=None, password=None, **kwargs):
        try:
            user = User.objects.get(uid=uid)
        except User.DoesNotExist:
            return None
        else:
            if user.check_password(password):
                return user
        return None