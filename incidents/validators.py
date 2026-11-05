import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class ComplexityPasswordValidator:
    """
    Validate that the password satisfies high-security enterprise complexity:
    - At least one uppercase letter [A-Z]
    - At least one lowercase letter [a-z]
    - At least one numeric digit [0-9]
    - At least one special symbol [!@#$%^&*(),.?":{}|<>-_]
    """

    def validate(self, password, user=None):
        if not re.search(r"[A-Z]", password):
            raise ValidationError(
                _("The password must contain at least one uppercase letter (A-Z)."),
                code="password_no_upper",
            )
        if not re.search(r"[a-z]", password):
            raise ValidationError(
                _("The password must contain at least one lowercase letter (a-z)."),
                code="password_no_lower",
            )
        if not re.search(r"[0-9]", password):
            raise ValidationError(
                _("The password must contain at least one digit (0-9)."),
                code="password_no_digit",
            )
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_]", password):
            raise ValidationError(
                _("The password must contain at least one special character (!@#$%^&*(),.?\":{}|<>-_)."),
                code="password_no_symbol",
            )

    def get_help_text(self):
        return _(
            "Your password must contain at least one uppercase letter, "
            "one lowercase letter, one digit, and one special character."
        )
