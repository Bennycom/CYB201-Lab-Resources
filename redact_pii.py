"""
redact_pii.py
CYB201 - Lab 9: Privacy Compliance and Data Redaction
University of Benin  |  github.com/Bennycom/CYB201-Lab-Resources

PURPOSE
-------
This script reads the mock customer dataset (mock_customer_data.csv),
applies field-appropriate redaction rules, and writes a compliant copy
to mock_customer_data_REDACTED.csv. It also writes a redaction log
(redaction_log.csv) recording exactly what was changed, in which
record, and by which technique -- this log is your evidence of
compliance if the NDPC ever requests it.

HOW TO RUN
----------
    python3 redact_pii.py

Make sure mock_customer_data.csv is in the same folder as this script
before running. If you see a FileNotFoundError, that is the most
likely cause.

YOUR TASK
---------
Read every function below, understand what it does, then COMPLETE the
two TODO sections. The script will run without completing the TODOs,
but PhoneNumber and Email will remain unredacted in the output file
until you do.
"""

import csv
import hashlib

INPUT_FILE  = "mock_customer_data.csv"
OUTPUT_FILE = "mock_customer_data_REDACTED.csv"
LOG_FILE    = "redaction_log.csv"


# ──────────────────────────────────────────────────────────────────────────
# REDACTION FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────

def mask_keep_last4(value: str) -> str:
    """Replace all but the last 4 characters with asterisks.

    Used for fields where staff may still need partial verification —
    for example, confirming a caller's identity against the last 4
    digits of their registered phone number — without exposing the
    full value.

    Note: always strip separators (hyphens, spaces) before calling
    this function on card numbers or phone numbers, so the character
    count is predictable.

    Examples:
        mask_keep_last4("4716203199814452") -> "************4452"
        mask_keep_last4("08031234567")      -> "*******4567"
    """
    if not value:
        return value
    if len(value) <= 4:
        # Value is 4 chars or fewer: nothing left to mask, return as-is.
        # This is safe -- a 3-digit CVV would return itself, but CVVs
        # should not appear in this dataset.
        return value
    visible = value[-4:]
    return "*" * (len(value) - 4) + visible


def hash_identifier(value: str) -> str:
    """Irreversibly hash a unique identifier (NIN, BVN).

    SHA-256 is a one-way cryptographic function: it lets a system
    confirm that two records belong to the same person (same hash =
    same original value) without ever storing or recovering the real
    number. This satisfies the NDPA 2023 Section 39 requirement to
    implement appropriate technical measures, and supports the Right
    to Erasure (S.34(1)(d)) because the original cannot be recovered
    from the digest alone.

    The digest is truncated to 12 characters for readability in this
    lab exercise. In production you would keep the full 64-character
    hex digest.

    Examples:
        hash_identifier("12345678901") -> "254aa248acb4"
        hash_identifier("")            -> ""   (empty in, empty out)
    """
    if not value:
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return digest[:12]


def redact_health_note(value: str) -> str:
    """Fully remove a health note, replacing it with a redaction marker.

    Health information is sensitive personal data under NDPA 2023
    Section 30. We remove it entirely rather than masking it because a
    partially visible health note can still be identifying or
    stigmatising -- for example, even the first letter of a condition
    may narrow it down significantly.

    Examples:
        redact_health_note("Diabetic — insulin dependent")
            -> "[REDACTED - SENSITIVE PERSONAL DATA, NDPA S.30]"
        redact_health_note("")
            -> ""   (blank note: nothing to redact)
    """
    if not value:
        return value
    return "[REDACTED - SENSITIVE PERSONAL DATA, NDPA S.30]"


# ──────────────────────────────────────────────────────────────────────────
# MAIN PROCESSING
# ──────────────────────────────────────────────────────────────────────────

def main():
    log_rows = []

    # Open with encoding="utf-8-sig" so the script works whether the CSV
    # was created on a Mac/Linux editor (plain UTF-8) OR saved from Excel
    # on Windows (UTF-8 with BOM). The "sig" variant silently strips the
    # BOM if present and has no effect if absent.
    with open(INPUT_FILE, newline="", encoding="utf-8-sig") as f_in:
        reader = csv.DictReader(f_in)
        rows = list(reader)
        fieldnames = reader.fieldnames

    if not rows:
        print(f"ERROR: {INPUT_FILE} appears to be empty. Check the file and try again.")
        return

    if fieldnames is None:
        print(f"ERROR: Could not read column headers from {INPUT_FILE}.")
        print("Make sure the first row contains: RecordID,FullName,NIN,BVN,...")
        return

    for row in rows:
        record_id = row.get("RecordID", "UNKNOWN")

        # ── NIN: irreversible hash ─────────────────────────────────────
        original = row["NIN"]
        row["NIN"] = hash_identifier(original)
        log_rows.append([record_id, "NIN", "sha256_hash_12char", "irreversible"])

        # ── BVN: irreversible hash ─────────────────────────────────────
        original = row["BVN"]
        row["BVN"] = hash_identifier(original)
        log_rows.append([record_id, "BVN", "sha256_hash_12char", "irreversible"])

        # ── CardNumber: mask, keep last 4 (mirrors PCI-DSS practice) ──
        # Strip hyphens first so the mask length is predictable.
        original = row["CardNumber"].replace("-", "")
        row["CardNumber"] = mask_keep_last4(original)
        log_rows.append([record_id, "CardNumber", "mask_last4", "partial"])

        # ── HealthNote: full removal (NDPA S.30 sensitive data) ───────
        # Only log the action if a note was actually present.
        if row.get("HealthNote", "").strip():
            row["HealthNote"] = redact_health_note(row["HealthNote"])
            log_rows.append([record_id, "HealthNote", "full_removal", "irreversible"])

        # ==============================================================
        # TODO 1 — PhoneNumber  (Part B, Question 3 in your worksheet)
        #
        # Decide how PhoneNumber should be treated and implement it.
        # Use mask_keep_last4(), hash_identifier(), or write your own rule.
        #
        # Questions to answer in your worksheet:
        #   - Should a call-centre agent be able to verify the last 4
        #     digits of a caller's phone number?
        #   - If yes, masking is appropriate. If no, hashing is safer.
        #
        # Uncomment and complete the lines below:
        #
        # original = row["PhoneNumber"]
        # row["PhoneNumber"] = ...your technique here...
        # log_rows.append([record_id, "PhoneNumber", "your_technique", "reversible_or_not"])
        # ==============================================================

        # ==============================================================
        # TODO 2 — Email  (Part B, Question 4 in your worksheet)
        #
        # Decide how Email should be treated and implement it.
        #
        # Hint: consider treating the local part (before the @) and the
        # domain (after the @) differently. A support agent may need to
        # know which email provider (@gmail.com vs @yahoo.com) without
        # seeing the full address.
        #
        # Uncomment and complete the lines below:
        #
        # original = row["Email"]
        # row["Email"] = ...your technique here...
        # log_rows.append([record_id, "Email", "your_technique", "reversible_or_not"])
        # ==============================================================

    # Write redacted CSV
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # Write redaction log
    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f_log:
        writer = csv.writer(f_log)
        writer.writerow(["RecordID", "Field", "TechniqueApplied", "Reversibility"])
        writer.writerows(log_rows)

    print(f"Done.")
    print(f"  Redacted data  -> {OUTPUT_FILE}")
    print(f"  Redaction log  -> {LOG_FILE}")
    print()
    print("Next step: open both output files and complete Part B of your worksheet.")
    if any(True for row in rows
           if not row.get("PhoneNumber", "").startswith("*")
           and not row.get("PhoneNumber", "") == ""):
        print()
        print("NOTE: PhoneNumber and Email are still unredacted.")
        print("Complete TODO 1 and TODO 2 in the script, then re-run.")


if __name__ == "__main__":
    main()
