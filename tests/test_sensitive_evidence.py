"""Corroborating-evidence detectors for the sensitive-content analyzer (ml/sensitive/evidence.py).

They must fire on text that actually contains something private and stay silent on the public prose
(policies, licences, statements, news, textbooks) a topic detector confuses with it.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.sensitive.evidence import find_evidence  # noqa: E402


@pytest.mark.parametrize("text", [
    "Employee salary list: Alice 142000, Bob 98000, Carol 175000, confidential.",
    "CONFIDENTIAL\nQ3 compensation review\nAlice 142000\nBob 98000",
    "Please keep this INTERNAL USE ONLY until the announcement.",
    "Privileged & Confidential - attorney-client communication",
    "Do not forward this memo outside the finance team.",
])
def test_confidentiality_marking_is_detected(text):
    assert "confidentiality-marker" in find_evidence(text)


@pytest.mark.parametrize("text", [
    "We keep your personal information confidential and never sell it.",
    "Our confidentiality obligations are described in section 4 of these terms.",
    "You agree to keep the Confidential Information of the other party secret.",
    "This license does not grant rights to use proprietary trademarks.",
])
def test_the_word_in_ordinary_prose_is_not_a_marking(text):
    assert "confidentiality-marker" not in find_evidence(text)


def test_passport_number_and_home_address_are_two_identity_signals():
    ev = find_evidence("My passport number is X1234567 and my home address is 12 Elm St.")
    assert "id-number" in ev and "home-address" in ev


def test_ssn_and_date_of_birth():
    ev = find_evidence("Applicant SSN 536-90-4399, date of birth 14 March 1988.")
    assert "id-number" in ev and "date-of-birth" in ev


@pytest.mark.parametrize("text", [
    "Enter your passport number on the form and we will check it against the register.",
    "Passport control is open from 6 am. Please keep your documents ready.",
    "The street address field should contain the number and street, e.g. 12 Elm St.",
])
def test_identity_words_without_a_value_do_not_fire(text):
    ev = find_evidence(text)
    assert "id-number" not in ev and "home-address" not in ev


def test_name_amount_list_needs_three_items_with_one_amount_each():
    assert "name-amount-list" in find_evidence("Alice 142000, Bob 98000, Carol 175000")
    assert "name-amount-list" not in find_evidence("Alice 142000, Bob 98000")
    # a financial-statement row has several columns, a year is not an amount
    assert "name-amount-list" not in find_evidence("Revenue 12,500 11,200 10,900\nNet Income 5,363 4,869 5,058\nTotal Assets 81,000 75,000 70,000")
    assert "name-amount-list" not in find_evidence("Directive of July 2014 amending Regulation of March 2013 and June 2012")


def test_patient_narrative_needs_age_and_clinical_phrase():
    assert "patient-narrative" in find_evidence("SUBJECTIVE: This 23-year-old white female presents with complaint of allergies.")
    assert "patient-narrative" not in find_evidence("Children under 5 years old should not take this drug.")
    assert "patient-narrative" not in find_evidence("Diabetes mellitus is a chronic metabolic disease with a history of research.")


def test_clinical_note_is_a_form_with_several_section_headings():
    note = "CHIEF COMPLAINT: Itchy rash.\nHISTORY OF PRESENT ILLNESS: He awoke this morning with itching.\nMEDICATIONS: None."
    assert "clinical-note" in find_evidence(note)
    assert "clinical-note" not in find_evidence("DIAGNOSIS: the textbook describes several kinds of anemia.")   # one heading
    assert "clinical-note" not in find_evidence("The assessment and the impression of the committee: both were positive.")  # not headings


def test_scan_is_capped_so_a_huge_body_stays_cheap():
    import time
    from ml.sensitive.evidence import MAX_SCAN_CHARS
    big = "lorem ipsum dolor sit amet " * 400_000                       # ~10 MB of prose
    t0 = time.time()
    assert find_evidence(big) == []
    assert time.time() - t0 < 2.0
    # a marking only past the cap is not seen; one inside it is
    assert find_evidence("x " * (MAX_SCAN_CHARS // 2 + 10) + "\nCONFIDENTIAL\n") == []
    assert "confidentiality-marker" in find_evidence("CONFIDENTIAL\n" + "x " * (MAX_SCAN_CHARS // 2 + 10))


def test_plain_text_has_no_evidence():
    assert find_evidence("The quarterly meeting is on Tuesday at 3pm in room 4.") == []
    assert find_evidence("") == []
