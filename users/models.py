from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django_otp.plugins.otp_totp.models import TOTPDevice

class Student(AbstractUser):
    # Student-defined Unique Identifier (UID)
    uid = models.CharField(max_length=100, unique=True, default = "undefined")

    passed_SDCA = models.BooleanField(default=False)
    passed_LTPI = models.BooleanField(default=False)
    passed_MTPI = models.BooleanField(default=False)
    passed_RSPS = models.BooleanField(default=False)
    passed_S_BTC = models.BooleanField(default=False)
    passed_S_ETH = models.BooleanField(default=False)
    passed_S_ALT = models.BooleanField(default=False)
    passed_INTERVIEW = models.BooleanField(default=False)
    is_banned = models.BooleanField(default=False)

    # Timeout feature
    timeout_until = models.DateTimeField(null=True, blank=True)


    # Add TOTP device relationship
    totp_device = models.ForeignKey(
        TOTPDevice,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name='student'
    )


    def __str__(self):
        return self.username

    @property
    def is_timeouted(self):
        """
        Property to check if the student is currently timed out.
        """
        if self.timeout_until is None:
            return False
        return self.timeout_until > timezone.now()

    def set_timeout(self, duration):
        """
        Set a timeout for the student. Duration should be a datetime.timedelta object.
        """
        self.timeout_until = timezone.now() + duration
        self.save()

    def clean(self):
        # Custom validation to ensure UID is unique
        if Student.objects.filter(uid=self.uid).exclude(id=self.id).exists():
            raise ValidationError({'uid': _("This UID is already in use.")})