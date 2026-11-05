from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from incidents.validators import ComplexityPasswordValidator


class PasswordComplexityPolicyTests(SimpleTestCase):
    """
    Automated security tests for enterprise password complexity policy.
    Ensures that weak or simplistic passwords cannot be set.
    """

    def setUp(self):
        self.validator = ComplexityPasswordValidator()

    def test_strong_compliant_password_passes(self):
        # 14+ chars with uppercase, lowercase, number, and symbol
        self.validator.validate("H@rd3ned!Desk2026")

    def test_missing_uppercase_is_rejected(self):
        with self.assertRaises(ValidationError) as cm:
            self.validator.validate("all_lowercase_123!@#")
        self.assertIn("uppercase letter", str(cm.exception))

    def test_missing_lowercase_is_rejected(self):
        with self.assertRaises(ValidationError) as cm:
            self.validator.validate("ALL_UPPERCASE_123!@#")
        self.assertIn("lowercase letter", str(cm.exception))

    def test_missing_digit_is_rejected(self):
        with self.assertRaises(ValidationError) as cm:
            self.validator.validate("NoDigitsAllowedHere!@#")
        self.assertIn("digit", str(cm.exception))

    def test_missing_special_character_is_rejected(self):
        with self.assertRaises(ValidationError) as cm:
            self.validator.validate("SimpleAlphanumeric123456")
        self.assertIn("special character", str(cm.exception))

    def test_help_text_provides_guidance(self):
        help_text = self.validator.get_help_text()
        self.assertIn("uppercase", help_text)
        self.assertIn("special character", help_text)
