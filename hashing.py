"""
Drishti - Hashing & Chain of Custody Module
Implements SHA-256 hashing, integrity verification, tamper simulation, and chain of custody tracking.
"""

import hashlib
import os
from datetime import datetime


def calculate_sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 hash string for raw bytes."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest().upper()


def calculate_sha256_file(file_path: str) -> str:
    """Computes SHA-256 hash string for a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().upper()


def get_file_type_badge(filename: str) -> str:
    """Returns file format category for badge display."""
    ext = os.path.splitext(filename)[1].lower()
    if ext in [".csv"]:
        return "Structured Log (CSV)"
    elif ext in [".txt", ".log"]:
        return "Communication Log (TXT)"
    elif ext in [".png", ".jpg", ".jpeg"]:
        return "Digital Screenshot (IMG)"
    elif ext in [".pdf"]:
        return "Digital Document (PDF)"
    return "Binary Evidence"


class EvidenceVault:
    """
    Manages Chain of Custody records in st.session_state.
    Stores initial hash at ingress time, current hash, status, and raw content for tamper restoration.
    """

    @staticmethod
    def register_evidence(filename: str, content_bytes: bytes, source: str = "Ingested File"):
        initial_hash = calculate_sha256_bytes(content_bytes)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")
        size_kb = round(len(content_bytes) / 1024, 2)
        
        return {
            "filename": filename,
            "file_type": get_file_type_badge(filename),
            "size_kb": f"{size_kb} KB",
            "initial_hash": initial_hash,
            "current_hash": initial_hash,
            "ingest_time": now_str,
            "source": source,
            "status": "VERIFIED",
            "original_content": content_bytes,
            "current_content": content_bytes,
            "tampered": False,
            "tamper_details": None
        }

    @staticmethod
    def verify_all(evidence_dict: dict) -> dict:
        """Re-computes hash for each item and updates status."""
        for name, item in evidence_dict.items():
            curr_hash = calculate_sha256_bytes(item["current_content"])
            item["current_hash"] = curr_hash
            if curr_hash == item["initial_hash"]:
                item["status"] = "VERIFIED"
                item["tampered"] = False
                item["tamper_details"] = None
            else:
                item["status"] = "TAMPERED"
                item["tampered"] = True
        return evidence_dict

    @staticmethod
    def simulate_tampering(evidence_dict: dict, target_file: str = "transactions.csv") -> dict:
        """
        Simulates an unauthorized insider or malware tampering with evidence.
        Alters a transaction row in memory/bytes, recomputes current hash, and marks TAMPERED.
        """
        if target_file not in evidence_dict:
            # Fallback to first available file
            if not evidence_dict:
                return evidence_dict
            target_file = list(evidence_dict.keys())[0]

        item = evidence_dict[target_file]
        original_text = item["current_content"].decode("utf-8", errors="ignore")

        # Dramatically tamper a critical value: alter the fraud amount or receiver
        if "49000.00" in original_text:
            tampered_text = original_text.replace("49000.00", "490.00")
            detail = "Fraud amount modified from INR 49,000.00 to INR 490.00 (Insider Record Alteration)"
        elif "Ramesh Traders" in original_text:
            tampered_text = original_text.replace("Ramesh Traders", "Authorized Bank Utility")
            detail = "Receiver identity altered from 'Ramesh Traders' to 'Authorized Bank Utility'"
        else:
            tampered_text = original_text + "\n# TAMPERED_ENTRY_BY_INTRUDER_MALICIOUS_LOG"
            detail = "Unauthorized row injection at EOF"

        tampered_bytes = tampered_text.encode("utf-8")
        new_hash = calculate_sha256_bytes(tampered_bytes)

        item["current_content"] = tampered_bytes
        item["current_hash"] = new_hash
        item["status"] = "TAMPERED"
        item["tampered"] = True
        item["tamper_details"] = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S IST"),
            "target": target_file,
            "description": detail,
            "initial_hash": item["initial_hash"],
            "tampered_hash": new_hash
        }
        return evidence_dict

    @staticmethod
    def restore_all(evidence_dict: dict) -> dict:
        """Restores original byte content for all files and re-verifies."""
        for name, item in evidence_dict.items():
            item["current_content"] = item["original_content"]
            item["current_hash"] = item["initial_hash"]
            item["status"] = "VERIFIED"
            item["tampered"] = False
            item["tamper_details"] = None
        return evidence_dict
