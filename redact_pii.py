"""
redact_pii.py
CYB201 - Lab 9: Privacy Compliance and Data Redaction

This script reads the mock customer dataset (mock_customer_data.csv),
applies field-appropriate redaction rules, and writes a compliant copy
to mock_customer_data_REDACTED.csv. It also writes a redaction log
(redaction_log.csv) recording exactly what was changed, in which
record, for which field -- this log is your evidence of compliance.

Run it with:
    python3 redact_pii.py

You are expected to read every line, understand what each rule does,
and then COMPLETE the two TODO sections yourself.
"""

import csv
import hashlib

INPUT_FILE = "mock_customer_data.csv"
OUTPUT_FILE = "mock_customer_data_REDACTED.csv"
LOG_FILE = "redaction_log.csv"


def mask_keep_last4(value: str) -> str:
    """Replace all but the last 4 characters with asterisks.
    Used for fields where staff may still need partial verification,
    e.g. confirming a caller's identity against the last 4 digits
    of an account number."""
    if not value:
        return value
    visible = value[-4:]
    return "*" * (len(value) - 4) + visible


def hash_identifier(value: str) -> str:
    """Irreversibly hash a unique identifier (NIN, BVN, card number).
    Hashing is one-way: it lets you confirm two records refer to the
    same person without ever storing the real number. This satisfies
    the NDPA Section 39 requirement to protect sensitive identifiers
    at rest, and supports the Right to Erasure (NDPA S.34(1)(d)) because
    the original value cannot be recovered from the hash."""
    if not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]  # shortened for readability in this lab


def redact_health_note(value: str) -> str:
    """Health information is sensitive personal data under NDPA Section 30.
    For this lab, we remove it entirely rather than mask it, because a
    partially visible health note can still be identifying or stigmatising."""
    if not value:
        return value
    return "[REDACTED - SENSITIVE PERSONAL DATA, NDPA S.30]"


def main():
    log_rows = []

    with open(INPUT_FILE, newline="", encoding="utf-8") as f_in:
        reader = csv.DictReader(f_in)
        rows = list(reader)
        fieldnames = reader.fieldnames

    for row in rows:
        record_id = row["RecordID"]

        # --- NIN: irreversible hash (sensitive identifier) ---
        original = row["NIN"]
        row["NIN"] = hash_identifier(original)
        log_rows.append([record_id, "NIN", "hash", "irreversible"])

        # --- BVN: irreversible hash (sensitive identifier) ---
        original = row["BVN"]
        row["BVN"] = hash_identifier(original)
        log_rows.append([record_id, "BVN", "hash", "irreversible"])

        # --- Card number: mask, keep last 4 (PCI-DSS pattern) ---
        original = row["CardNumber"]
        row["CardNumber"] = mask_keep_last4(original.replace("-", ""))
        log_rows.append([record_id, "CardNumber", "mask_last4", "reversible-by-reissue-only"])

        # --- Health note: full removal (sensitive personal data) ---
        if row.get("HealthNote"):
            row["HealthNote"] = redact_health_note(row["HealthNote"])
            log_rows.append([record_id, "HealthNote", "full_removal", "irreversible"])

        # =====================================================
        # TODO 1 (Part B, Question 3 in your worksheet):
        # Decide how PhoneNumber should be treated, and implement it
        # here using either mask_keep_last4() or a new rule of your own.
        # Justify your choice in the worksheet: should support staff be
        # able to verify a caller using the masked number, or not?
        #
        # row["PhoneNumber"] = ...
        # =====================================================

        # =====================================================
        # TODO 2 (Part B, Question 4 in your worksheet):
        # Decide how Email should be treated. Consider: does the local
        # part (before the @) need full masking, or only partial masking?
        # Implement your rule here.
        #
        # row["Email"] = ...
        # =====================================================

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f_log:
        writer = csv.writer(f_log)
        writer.writerow(["RecordID", "Field", "TechniqueApplied", "Reversibility"])
        writer.writerows(log_rows)

    print(f"Done. Wrote {OUTPUT_FILE} and {LOG_FILE}.")
    print("Open both files and complete Part B of your worksheet.")


if __name__ == "__main__":
    main()
