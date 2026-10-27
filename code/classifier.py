"""Request loading and intent classification module."""

import re
from typing import Tuple, Optional


class RequestClassifier:
    """Classifies user request text to determine if deletion is authorized."""

    # Explicit non-deletion exclusion phrases where user declines deletion or asks to preserve account
    NON_DELETION_PATTERNS = [
        re.compile(r"leave\s+the\s+account\s+active", re.IGNORECASE),
        re.compile(r"not\s+asking\s+for\s+deletion", re.IGNORECASE),
        re.compile(r"keep\s+the\s+account\s+as\s+it\s+is", re.IGNORECASE),
        re.compile(r"leave\s+my\s+profile.*in\s+place", re.IGNORECASE),
        re.compile(r"continue\s+using\s+the\s+service", re.IGNORECASE),
        re.compile(r"stop\s+the\s+promotional\s+emails", re.IGNORECASE),
        re.compile(r"mobile\s+number.*replace\s+it\s+with\s+the\s+new\s+one", re.IGNORECASE),
        re.compile(r"download\s+my\s+account\s+information", re.IGNORECASE),
        re.compile(r"copy\s+of\s+last\s+year'?s?\s+invoices", re.IGNORECASE),
        re.compile(r"change\s+the\s+email\s+address\s+used\s+for\s+this\s+account", re.IGNORECASE),
        re.compile(r"do\s+not\s+close\s+the\s+account", re.IGNORECASE),
        re.compile(r"without\s+removing\s+any\s+of\s+my\s+records", re.IGNORECASE),
        re.compile(r"remove\s+me\s+from\s+marketing\s+lists\s+only", re.IGNORECASE),
        re.compile(r"information\s+request,\s+not\s+a\s+request\s+to\s+erase\s+it", re.IGNORECASE),
        re.compile(r"don't\s+delete\s+or\s+change\s+anything", re.IGNORECASE),
        re.compile(r"(do\s+not|don't)\s+(delete|close|erase|remove)", re.IGNORECASE),
        re.compile(r"without\s+(deleting|removing|erasing|closing)", re.IGNORECASE),
    ]

    # Multilingual deletion authorization verbs / nouns
    DELETION_PATTERNS = [
        re.compile(r"\b(delet(e|ed|ing|ion|ions)?|eras(e|ed|ing|ure)?|clos(e|ed|ing)?|remov(e|ed|ing|al)?|clean(ed|ing)?)\b", re.IGNORECASE),
        re.compile(r"\b(gone|unlinked?|de-identif\w*)\b", re.IGNORECASE),
        re.compile(r"\b(supprim(er?|é|ée|e)?|suppression|effac(er?|é|ée)?)\b", re.IGNORECASE),
        re.compile(r"\b(elimin(ar?|ado|ada|ación)?|borr(ar?|ado|ada)?)\b", re.IGNORECASE),
        re.compile(r"\b(exclu(são|ir?|ído|ída)?)\b", re.IGNORECASE),
        re.compile(r"\b(lösch(en?|ung|t)?|entfern(en?|t)?)\b", re.IGNORECASE),
        re.compile(r"(削除|消去)", re.IGNORECASE),
        re.compile(r"(삭제|폐기)", re.IGNORECASE),
        re.compile(r"(حذف|إغلاق)", re.IGNORECASE),
    ]

    @classmethod
    def classify_intent(cls, request_text: str) -> Tuple[bool, str]:
        """Returns (is_deletion_authorized, reason/category).
        
        If is_deletion_authorized is False, the case status must be NOT_APPLICABLE.
        """
        if not request_text:
            return False, "EMPTY_REQUEST"

        # Check explicit exclusion patterns first
        for pat in cls.NON_DELETION_PATTERNS:
            if pat.search(request_text):
                return False, f"NON_DELETION_EXCLUSION: {pat.pattern}"

        # Check deletion authorization keywords
        for pat in cls.DELETION_PATTERNS:
            if pat.search(request_text):
                return True, f"DELETION_AUTHORIZED: {pat.pattern}"

        # If neither matches, default to False or require LLM review
        return False, "UNRECOGNIZED_INTENT"
