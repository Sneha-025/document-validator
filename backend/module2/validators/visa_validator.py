"""
Visa document validator for Module 2.

This validator performs prototype-level structural,
date, category, stay-duration, and cross-document checks.

It does NOT:
- perform OCR
- detect document tampering
- perform face verification
- access government databases
- make a definitive fraud/fake-person determination
"""

from datetime import date, datetime

from module2.schemas import (
    CheckStatus,
    OverallStatus,
    Severity,
    ValidationCheck,
)

from module2.rules.visa_rules import VISA_RULES


class VisaValidator:
    """Validate OCR-extracted visa information."""

    def validate(self, data: dict, passport_data: dict | None = None) -> dict:
        checks = []

        # ---------------------------------------------------------
        # Helper
        # ---------------------------------------------------------

        def add_check(
            rule_id,
            status,
            severity,
            message,
            field=None,
            details=None,
        ):
            checks.append(
                ValidationCheck(
                    rule_id=rule_id,
                    status=status,
                    severity=severity,
                    message=message,
                    field=field,
                    details=details,
                )
            )

        # ---------------------------------------------------------
        # Basic document type
        # ---------------------------------------------------------

        document_type = str(
            data.get("document_type", "")
        ).upper()

        if document_type == "VISA":
            add_check(
                "COMMON-001",
                CheckStatus.PASS,
                Severity.INFO,
                "Document type is VISA.",
                "document_type",
            )
        else:
            add_check(
                "COMMON-001",
                CheckStatus.FAIL,
                Severity.HIGH,
                "Document type must be VISA.",
                "document_type",
            )

        # ---------------------------------------------------------
        # VISA-001: Visa number present
        # ---------------------------------------------------------

        visa_number = data.get("visa_number")

        if visa_number:
            add_check(
                "VISA-001",
                CheckStatus.PASS,
                Severity.INFO,
                "Visa number is present.",
                "visa_number",
            )
        else:
            add_check(
                "VISA-001",
                CheckStatus.FAIL,
                Severity.HIGH,
                "Visa number is missing.",
                "visa_number",
            )

        # ---------------------------------------------------------
        # VISA-002: Visa number structure
        # ---------------------------------------------------------

        if visa_number:
            visa_number_clean = str(visa_number).strip()

            valid_structure = (
                5 <= len(visa_number_clean) <= 20
                and all(
                    char.isalnum() or char in "-/"
                    for char in visa_number_clean
                )
            )

            if valid_structure:
                add_check(
                    "VISA-002",
                    CheckStatus.PASS,
                    Severity.INFO,
                    "Visa number has a structurally acceptable format.",
                    "visa_number",
                )
            else:
                add_check(
                    "VISA-002",
                    CheckStatus.FAIL,
                    Severity.MEDIUM,
                    "Visa number does not match the configured prototype structure.",
                    "visa_number",
                )

        # ---------------------------------------------------------
        # VISA-003: Visa type present
        # ---------------------------------------------------------

        visa_type = data.get("visa_type")

        if visa_type:
            add_check(
                "VISA-003",
                CheckStatus.PASS,
                Severity.INFO,
                "Visa type is present.",
                "visa_type",
            )
        else:
            add_check(
                "VISA-003",
                CheckStatus.FAIL,
                Severity.HIGH,
                "Visa type is missing.",
                "visa_type",
            )

        # ---------------------------------------------------------
        # VISA-004: Visa type supported
        # ---------------------------------------------------------

        if visa_type:
            normalized_type = str(visa_type).strip().upper()

            supported_types = {
                "TOURIST",
                "BUSINESS",
                "STUDENT",
                "EMPLOYMENT",
                "TRANSIT",
                "MEDICAL",
                "CONFERENCE",
                "ENTRY",
                "OTHER",
            }

            if normalized_type in supported_types:
                add_check(
                    "VISA-004",
                    CheckStatus.PASS,
                    Severity.INFO,
                    "Visa type is present in the prototype category registry.",
                    "visa_type",
                )
            else:
                add_check(
                    "VISA-004",
                    CheckStatus.WARNING,
                    Severity.HIGH,
                    "Visa type is not present in the prototype category registry.",
                    "visa_type",
                    {"value": visa_type},
                )

        # ---------------------------------------------------------
        # Date parsing helper
        # ---------------------------------------------------------

        def parse_date(value):
            if not value:
                return None

            if isinstance(value, date):
                return value

            try:
                return datetime.strptime(
                    str(value),
                    "%Y-%m-%d",
                ).date()
            except ValueError:
                return None

        # ---------------------------------------------------------
        # VISA-005: Date parsing
        # ---------------------------------------------------------

        date_fields = [
            "issue_date",
            "valid_from",
            "expiry_date",
            "entry_date",
        ]

        parsed_dates = {}
        invalid_dates = []

        for field in date_fields:
            if data.get(field) is not None:
                parsed = parse_date(data.get(field))

                if parsed is None:
                    invalid_dates.append(field)
                else:
                    parsed_dates[field] = parsed

        if invalid_dates:
            add_check(
                "VISA-005",
                CheckStatus.FAIL,
                Severity.HIGH,
                "One or more visa dates are invalid calendar dates.",
                "dates",
                {"invalid_fields": invalid_dates},
            )
        elif parsed_dates:
            add_check(
                "VISA-005",
                CheckStatus.PASS,
                Severity.INFO,
                "Provided visa dates are valid calendar dates.",
                "dates",
            )
        else:
            add_check(
                "VISA-005",
                CheckStatus.NOT_CHECKED,
                Severity.HIGH,
                "No visa validity dates were provided.",
                "dates",
            )

        # ---------------------------------------------------------
        # VISA-006: Validity order
        # ---------------------------------------------------------

        start_date = (
            parsed_dates.get("valid_from")
            or parsed_dates.get("issue_date")
        )

        expiry_date = parsed_dates.get("expiry_date")

        if start_date and expiry_date:
            if start_date <= expiry_date:
                add_check(
                    "VISA-006",
                    CheckStatus.PASS,
                    Severity.INFO,
                    "Visa validity dates are in the correct order.",
                    "dates",
                )
            else:
                add_check(
                    "VISA-006",
                    CheckStatus.FAIL,
                    Severity.HIGH,
                    "Visa start date is after the expiry date.",
                    "dates",
                )
        else:
            add_check(
                "VISA-006",
                CheckStatus.NOT_CHECKED,
                Severity.HIGH,
                "Visa validity order could not be evaluated.",
                "dates",
            )

        # ---------------------------------------------------------
        # VISA-007: Current validity
        # ---------------------------------------------------------

        screening_date = parse_date(
            data.get("screening_date")
        ) or date.today()

        if start_date and expiry_date:
            if screening_date < start_date:
                add_check(
                    "VISA-007",
                    CheckStatus.WARNING,
                    Severity.HIGH,
                    "Visa validity has not started on the screening date.",
                    "dates",
                    {"screening_date": str(screening_date)},
                )
            elif screening_date > expiry_date:
                add_check(
                    "VISA-007",
                    CheckStatus.FAIL,
                    Severity.HIGH,
                    "Visa is expired on the screening date.",
                    "expiry_date",
                    {"screening_date": str(screening_date)},
                )
            else:
                add_check(
                    "VISA-007",
                    CheckStatus.PASS,
                    Severity.INFO,
                    "Visa is within its configured validity period.",
                    "dates",
                )
        else:
            add_check(
                "VISA-007",
                CheckStatus.NOT_CHECKED,
                Severity.HIGH,
                "Current visa validity could not be evaluated.",
                "dates",
            )

        # ---------------------------------------------------------
        # VISA-008: Entry type
        # ---------------------------------------------------------

        entry_type = data.get("entry_type")

        if entry_type:
            normalized_entry = str(entry_type).strip().upper()

            if normalized_entry in {
                "SINGLE",
                "DOUBLE",
                "MULTIPLE",
            }:
                add_check(
                    "VISA-008",
                    CheckStatus.PASS,
                    Severity.INFO,
                    "Visa entry type is recognized.",
                    "entry_type",
                )
            else:
                add_check(
                    "VISA-008",
                    CheckStatus.WARNING,
                    Severity.MEDIUM,
                    "Visa entry type is not in the prototype registry.",
                    "entry_type",
                )
        else:
            add_check(
                "VISA-008",
                CheckStatus.NOT_CHECKED,
                Severity.MEDIUM,
                "Entry type was not provided.",
                "entry_type",
            )

        # ---------------------------------------------------------
        # VISA-009: Stay duration
        # ---------------------------------------------------------

        stay_duration = data.get("stay_duration_days")

        if stay_duration is not None:
            try:
                stay_duration = int(stay_duration)

                if 1 <= stay_duration <= 3650:
                    add_check(
                        "VISA-009",
                        CheckStatus.PASS,
                        Severity.INFO,
                        "Stay duration is within the prototype sanity range.",
                        "stay_duration_days",
                    )
                else:
                    add_check(
                        "VISA-009",
                        CheckStatus.FAIL,
                        Severity.HIGH,
                        "Stay duration is outside the configured prototype range.",
                        "stay_duration_days",
                    )

            except (TypeError, ValueError):
                add_check(
                    "VISA-009",
                    CheckStatus.FAIL,
                    Severity.HIGH,
                    "Stay duration must be a valid number of days.",
                    "stay_duration_days",
                )
        else:
            add_check(
                "VISA-009",
                CheckStatus.NOT_CHECKED,
                Severity.HIGH,
                "Stay duration was not provided.",
                "stay_duration_days",
            )

        # ---------------------------------------------------------
        # Cross-document checks
        # ---------------------------------------------------------

        if passport_data:
            # VISA-010: Passport number match
            visa_passport = data.get("passport_number")
            reference_passport = passport_data.get("passport_number")

            if visa_passport and reference_passport:
                if (
                    str(visa_passport).strip().upper()
                    == str(reference_passport).strip().upper()
                ):
                    add_check(
                        "VISA-010",
                        CheckStatus.PASS,
                        Severity.INFO,
                        "Visa passport number matches the referenced passport.",
                        "passport_number",
                    )
                else:
                    add_check(
                        "VISA-010",
                        CheckStatus.FAIL,
                        Severity.HIGH,
                        "Visa passport number does not match the referenced passport.",
                        "passport_number",
                    )
            else:
                add_check(
                    "VISA-010",
                    CheckStatus.NOT_CHECKED,
                    Severity.HIGH,
                    "Passport number comparison could not be performed.",
                    "passport_number",
                )

            # VISA-011: Name match
            visa_name = data.get("name")
            passport_name = passport_data.get("name")

            if visa_name and passport_name:
                if (
                    str(visa_name).strip().upper()
                    == str(passport_name).strip().upper()
                ):
                    add_check(
                        "VISA-011",
                        CheckStatus.PASS,
                        Severity.INFO,
                        "Visa holder name matches the referenced passport.",
                        "name",
                    )
                else:
                    add_check(
                        "VISA-011",
                        CheckStatus.FAIL,
                        Severity.HIGH,
                        "Visa holder name does not match the referenced passport.",
                        "name",
                    )
            else:
                add_check(
                    "VISA-011",
                    CheckStatus.NOT_CHECKED,
                    Severity.HIGH,
                    "Name comparison could not be performed.",
                    "name",
                )

            # VISA-012: Nationality match
            visa_nationality = data.get("nationality")
            passport_nationality = passport_data.get("nationality")

            if visa_nationality and passport_nationality:
                if (
                    str(visa_nationality).strip().upper()
                    == str(passport_nationality).strip().upper()
                ):
                    add_check(
                        "VISA-012",
                        CheckStatus.PASS,
                        Severity.INFO,
                        "Visa nationality matches passport nationality.",
                        "nationality",
                    )
                else:
                    add_check(
                        "VISA-012",
                        CheckStatus.WARNING,
                        Severity.MEDIUM,
                        "Visa nationality differs from passport nationality.",
                        "nationality",
                    )
            else:
                add_check(
                    "VISA-012",
                    CheckStatus.NOT_CHECKED,
                    Severity.MEDIUM,
                    "Nationality comparison could not be performed.",
                    "nationality",
                )

            # VISA-013: Passport validity
            passport_expiry = parse_date(
                passport_data.get("expiry_date")
            )

            if expiry_date and passport_expiry:
                if expiry_date <= passport_expiry:
                    add_check(
                        "VISA-013",
                        CheckStatus.PASS,
                        Severity.INFO,
                        "Visa expiry does not exceed passport expiry.",
                        "expiry_date",
                    )
                else:
                    add_check(
                        "VISA-013",
                        CheckStatus.WARNING,
                        Severity.HIGH,
                        "Visa expiry extends beyond passport expiry.",
                        "expiry_date",
                    )
            else:
                add_check(
                    "VISA-013",
                    CheckStatus.NOT_CHECKED,
                    Severity.HIGH,
                    "Visa/passport validity relationship could not be evaluated.",
                    "expiry_date",
                )

        else:
            for rule_id, message, field, severity in [
                (
                    "VISA-010",
                    "Passport number comparison requires passport data.",
                    "passport_number",
                    Severity.HIGH,
                ),
                (
                    "VISA-011",
                    "Name comparison requires passport data.",
                    "name",
                    Severity.HIGH,
                ),
                (
                    "VISA-012",
                    "Nationality comparison requires passport data.",
                    "nationality",
                    Severity.MEDIUM,
                ),
                (
                    "VISA-013",
                    "Visa/passport validity comparison requires passport data.",
                    "expiry_date",
                    Severity.HIGH,
                ),
            ]:
                add_check(
                    rule_id,
                    CheckStatus.NOT_CHECKED,
                    severity,
                    message,
                    field,
                )

        # ---------------------------------------------------------
        # VISA-014: Category-specific rules
        # ---------------------------------------------------------

        if visa_type:
            add_check(
                "VISA-014",
                CheckStatus.PASS,
                Severity.INFO,
                "Visa category is available for category-specific validation.",
                "visa_type",
            )
        else:
            add_check(
                "VISA-014",
                CheckStatus.NOT_CHECKED,
                Severity.HIGH,
                "Category-specific validation cannot be applied without a visa type.",
                "visa_type",
            )

        # ---------------------------------------------------------
        # VISA-015: Reference status
        # ---------------------------------------------------------

        add_check(
            "VISA-015",
            CheckStatus.NOT_CHECKED,
            Severity.HIGH,
            "Government/reference repository verification is not enabled in the prototype.",
            "reference_status",
            {
                "prototype": True,
                "future": "Authorized government or approved reference repository integration."
            },
        )

        # ---------------------------------------------------------
        # Overall status
        # ---------------------------------------------------------

        passed = sum(
            1 for check in checks
            if check.status == CheckStatus.PASS
        )

        failed = sum(
            1 for check in checks
            if check.status == CheckStatus.FAIL
        )

        warnings = sum(
            1 for check in checks
            if check.status == CheckStatus.WARNING
        )

        not_checked = sum(
            1 for check in checks
            if check.status == CheckStatus.NOT_CHECKED
        )

        if failed > 0:
            overall_status = OverallStatus.INVALID
        elif warnings > 0 or not_checked > 0:
            overall_status = OverallStatus.REVIEW
        else:
            overall_status = OverallStatus.VALID

        return {
            "document_type": "VISA",
            "overall_status": overall_status,
            "summary": {
                "total_checks": len(checks),
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "not_checked": not_checked,
            },
            "checks": checks,
        }