"""
Drishti - Entity Extraction & Cross-Source Correlation Module
Extracts cybercrime entities (phones, emails, IPs, bank accounts, UPI IDs, URLs)
and identifies pivotal cross-source correlations across all evidence files.
"""

import re
import os
import io
import pandas as pd
import pypdf


# Regex Patterns optimized for Indian cyber forensics
REGEX_PATTERNS = {
    "phone": r"(?:\+91[-\s]?)?[6-9]\d{4}[-\s]?\d{5}",
    "ip": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "email": r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
    "upi_id": r"\b[a-zA-Z0-9._-]+@(ok[a-zA-Z]+|paytm|upi|ybl|axl|sbi|icici|hdfcbank)\b",
    "bank_account": r"\b\d{11,16}\b",
    "url": r"https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9_.-]+)*",
    "ifsc": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "amount": r"(?:INR|₹|Rs\.?)\s*([0-9,]+(?:\.[0-9]{2})?)"
}


def clean_phone(p: str) -> str:
    """Normalizes phone formatting for cross-file matching."""
    cleaned = re.sub(r"[^\d+]", "", p)
    if not cleaned.startswith("+91") and len(cleaned) == 10:
        cleaned = "+91-" + cleaned[:5] + "-" + cleaned[5:]
    elif cleaned.startswith("+91") and len(cleaned) == 13:
        cleaned = "+91-" + cleaned[3:8] + "-" + cleaned[8:]
    return cleaned


def extract_text_from_evidence(filename: str, content_bytes: bytes) -> str:
    """Extracts searchable plain text from evidence bytes based on file format."""
    ext = os.path.splitext(filename)[1].lower()
    
    if ext in [".txt", ".log", ".csv"]:
        return content_bytes.decode("utf-8", errors="ignore")
    
    elif ext == ".pdf":
        try:
            reader = pypdf.PdfReader(io.BytesIO(content_bytes))
            text = ""
            for page in reader.pages:
                text += (page.extract_text() or "") + "\n"
            # Also append metadata text
            if reader.metadata:
                text += " ".join([str(v) for v in reader.metadata.values()])
            return text
        except Exception:
            return ""
            
    elif ext in [".png", ".jpg", ".jpeg"]:
        # Decode ASCII strings from image metadata/raw bytes
        try:
            raw_text = content_bytes.decode("latin-1", errors="ignore")
            # Extract printable strings
            printable_chunks = re.findall(r"[A-Za-z0-9+@:/._-]{5,}", raw_text)
            return " ".join(printable_chunks)
        except Exception:
            return ""
            
    return ""


def extract_entities_from_all_files(evidence_vault_dict: dict):
    """
    Scans all evidence files in vault and extracts unique entities,
    tracking the source files where each entity appears.
    """
    entity_records = []
    # Key: (entity_type, entity_value) -> set of filenames
    entity_source_map = {}

    for filename, item in evidence_vault_dict.items():
        raw_bytes = item.get("current_content", b"")
        text = extract_text_from_evidence(filename, raw_bytes)
        if not text:
            continue

        for etype, pattern in REGEX_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for m in matches:
                val = m.strip() if isinstance(m, str) else m[0].strip()
                if not val:
                    continue

                # Formatting refinements
                if etype == "phone":
                    val = clean_phone(val)
                elif etype == "ip":
                    # Filter local broadcast or 0.0.0.0
                    if val.startswith("0.") or val.startswith("255."):
                        continue
                elif etype == "bank_account":
                    # Filter common numeric codes like timestamps
                    if len(val) < 11 or val.startswith("2026"):
                        continue

                key = (etype, val)
                if key not in entity_source_map:
                    entity_source_map[key] = set()
                entity_source_map[key].add(filename)

    # Convert to structured list of records
    cross_source_links = []
    all_entities = []

    for (etype, val), sources in entity_source_map.items():
        is_cross = len(sources) >= 2
        
        # Categorize threat level
        is_threat = False
        threat_tag = "Neutral"
        if val in ["+91-98765-43210", "103.87.212.45", "981234564521", "ramesh.traders@okhdfcbank", "https://sbi-kyc-update-portal.in/verify"]:
            is_threat = True
            threat_tag = "CRITICAL / SCAMMER ENTITY"
        elif "Mule" in val or val in ["440918237712", "552109483319", "vikram.ent@okicici", "deepak99@oksbi"]:
            is_threat = True
            threat_tag = "HIGH / MULE ACCOUNT"
        elif val in ["30192837465", "rahul.sharma@oksbi", "122.161.45.10"]:
            threat_tag = "VICTIM PROFILE"

        rec = {
            "Entity_Type": etype.upper(),
            "Entity_Value": val,
            "Occurrence_Count": len(sources),
            "Source_Files": ", ".join(sorted(list(sources))),
            "Is_Cross_Source": is_cross,
            "Threat_Classification": threat_tag,
            "Is_Threat": is_threat
        }
        all_entities.append(rec)
        if is_cross:
            cross_source_links.append(rec)

    # Sort cross-source links by count descending
    cross_source_links.sort(key=lambda x: (x["Is_Threat"], x["Occurrence_Count"]), reverse=True)
    all_entities.sort(key=lambda x: (x["Is_Threat"], x["Occurrence_Count"]), reverse=True)

    return all_entities, cross_source_links
