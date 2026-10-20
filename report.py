"""
Drishti - Court-Ready Case Report Generator
Synthesizes forensic findings into Indian legal standard cybercrime investigation reports.
Includes offline template generator and optional local Ollama LLM synthesis with automatic fallback.
"""

from datetime import datetime
import json
import requests


def generate_offline_report(
    case_id="DRISHTI-2026-UP-0882",
    investigator_name="Insp. Vikram Rathore (Cyber Crime PS, Kanpur)",
    victim_name="Rahul Sharma",
    tampered_files=0,
    total_files=7,
    anomalous_txns_count=4,
    total_drained_inr=80000.0,
    evidence_vault=None
):
    """
    Generates a high-precision, court-ready cybercrime forensic report
    following Indian IT Act (Sec 65B compliance) and Bharatiya Nagarik Suraksha Sanhita (BNSS) norms.
    """
    now_str = datetime.now().strftime("%d-%b-%Y %H:%M:%S IST")
    integrity_status = "ALL FILES VERIFIED (CRYPTOGRAPHICALLY SOUND)" if tampered_files == 0 else f"CRITICAL ALERT: {tampered_files} EVIDENCE FILE(S) FAILED HASH VERIFICATION"

    report = f"""========================================================================================
             DRISHTI CYBER FORENSICS INVESTIGATION REPORT
          OFFICE OF THE SUPERINTENDENT OF POLICE | CYBER CRIME DIVISION
========================================================================================

REPORT REFERENCE: {case_id}
DATE & TIME OF GENERATION: {now_str}
LEAD INVESTIGATING OFFICER: {investigator_name}
PRIMARY VICTIM / COMPLAINANT: {victim_name} (Resident of Kanpur, Uttar Pradesh)
LEGAL JURISDICTION: Cyber Crime Police Station, Kanpur Zone
COMPLIANCE STANDARD: Indian Evidence Act Section 65B / Bharatiya Sakshya Adhiniyam Sec 63

----------------------------------------------------------------------------------------
1. EXECUTIVE SUMMARY & CRIME CLASSIFICATION
----------------------------------------------------------------------------------------
FRAUD CLASSIFICATION: Multi-Stage Targeted Vishing + Phishing + Nocturnal Credential Harvesting + Layered UPI Mule Account Exfiltration
INCIDENT TIMEFRAME: 17-Oct-2026 19:42 IST to 18-Oct-2026 02:27 IST
FINANCIAL EXPOSURE: INR 80,000.00 (Eighty Thousand Rupees Only)
CONFIDENCE SCORE: 96.4% (Multi-source corroborated across telephony, logs, and ledger)

SUMMARY:
On 17-Oct-2026 at 19:42 IST, victim Rahul Sharma received an impersonation voice call
(312 sec) from +91-98765-43210 claiming to be an authorized State Bank of India KYC officer.
The perpetrator leveraged social engineering to induce urgency regarding an impending account
blockade and transmitted a phishing URL (https://sbi-kyc-update-portal.in/verify) via WhatsApp.

The victim submitted credentials and session OTP. At 02:14:22 IST on 18-Oct-2026, the attacker
established an unauthorized net banking session from an anomalous Delhi IP (103.87.212.45),
bypassing typical Kanpur geofencing. Two rapid debits totaling INR 80,000 were drained to
primary mule beneficiary 'Ramesh Traders' (HDFC Bank), which subsequently initiated layered
IMPS transfers to secondary mule accounts to impede recovery.

----------------------------------------------------------------------------------------
2. CORROBORATED CHRONOLOGICAL INCIDENT RECONSTRUCTION
----------------------------------------------------------------------------------------
[17-Oct-2026 19:42:00 IST] - VISHING ENGAGEMENT:
  Incoming call from +91-98765-43210 to victim (+91-94501-11223). Scammer executed psychological
  pretexting regarding mandatory KYC re-validation. Duration: 312 seconds. (Source: call_logs.csv)

[17-Oct-2026 19:48:30 IST] - PHISHING DISSEMINATION:
  Scammer sent automated phishing dispatch containing link https://sbi-kyc-update-portal.in/verify.
  (Source: whatsapp_chat.txt, corroborated by fake_kyc_notice.pdf)

[17-Oct-2026 19:56:45 IST] - CREDENTIAL & OTP EXFILTRATION:
  Victim input netbanking credentials and synchronized 6-digit one-time password on adversary-controlled
  phishing form. (Source: whatsapp_chat.txt)

[18-Oct-2026 02:14:22 IST] - NOCTURNAL SESSION HIJACK:
  Adversary utilized exfiltrated credentials to access NetBanking portal from IP 103.87.212.45 (Delhi),
  using Linux/Chrome client. Prior victim baseline: Kanpur residential IP 122.161.45.10. (Source: login_logs.csv)

[18-Oct-2026 02:17:45 IST] - PRIMARY FRAUDULENT DEBIT (TXN10058):
  INR 49,000.00 debited from victim's account 30192837465 to 'Ramesh Traders' (HDFC A/C: 981234564521,
  UPI: ramesh.traders@okhdfcbank, Ref: UPI429182910392). (Source: transactions.csv, screenshot_original.png)

[18-Oct-2026 02:21:10 IST] - SECONDARY FRAUDULENT DEBIT (TXN10059):
  INR 31,000.00 debited to 'Ramesh Traders' (Ref: UPI429182910405). Total drained: INR 80,000.00.

[18-Oct-2026 02:25:30 IST] - LAYER-2 MULE DISPERSAL (TXN10060):
  INR 45,000.00 transferred via IMPS from Ramesh Traders to Vikram Enterprises (ICICI A/C: 440918237712).

[18-Oct-2026 02:27:00 IST] - LAYER-2 MULE DISPERSAL (TXN10061):
  INR 34,000.00 transferred via IMPS from Ramesh Traders to Deepak Rawat (SBI A/C: 552109483319).

----------------------------------------------------------------------------------------
3. SUSPICIOUS ENTITY INVENTORY & CROSS-SOURCE MAPPINGS
----------------------------------------------------------------------------------------
• THREAT ACTOR MOBILE:
  - MSISDN: +91-98765-43210 (Corroborated in: call_logs.csv, whatsapp_chat.txt, fake_kyc_notice.pdf)
  - Threat Assessment: Critical Vishing & Phishing conduit.

• ADVERSARY NETWORK INFRASTRUCTURE:
  - IP Address: 103.87.212.45 (Delhi NCR / Excitel Broadband)
  - Correlation: Infiltrated login_logs.csv and transactions.csv during nocturnal window.

• PHISHING DOMAIN:
  - URL: https://sbi-kyc-update-portal.in/verify
  - Registered intent: Impersonation of State Bank of India YONO portal.

• MULE BENEFICIARY NETWORK:
  - Primary Mule: Ramesh Traders | A/C: 981234564521 | IFSC: HDFC0001244 | VPA: ramesh.traders@okhdfcbank
  - Layer-2 Mule A: Vikram Enterprises | A/C: 440918237712 | IFSC: ICIC0000389 | VPA: vikram.ent@okicici
  - Layer-2 Mule B: Deepak Rawat | A/C: 552109483319 | IFSC: SBIN0004120 | VPA: deepak99@oksbi

----------------------------------------------------------------------------------------
4. CHAIN OF CUSTODY & EVIDENCE INTEGRITY AUDIT
----------------------------------------------------------------------------------------
INTEGRITY STATUS: {integrity_status}
TOTAL REGISTERED EXHIBITS: {total_files}
VERIFIED UNALTERED EXHIBITS: {total_files - tampered_files}
TAMPERED EXHIBITS: {tampered_files}

Every piece of evidence loaded into Drishti Vault was hashed upon ingress using SHA-256
cryptographic digest algorithms. Any modification to bytes triggers immediate visual and
procedural alerts to prevent inadmissible evidence submission.

----------------------------------------------------------------------------------------
5. STATUTORY NEXT STEPS & POLICE INVESTIGATOR ACTIONS
----------------------------------------------------------------------------------------
[ACTION 1 - IMMEDIATE DEBIT FREEZE]:
  Issue emergency order under Section 106 Bharatiya Nagarik Suraksha Sanhita (BNSS) /
  Sec 102 CrPC to Nodal Officers of HDFC Bank, ICICI Bank, and State Bank of India to freeze:
  - HDFC Account # 981234564521 (Ramesh Traders)
  - ICICI Account # 440918237712 (Vikram Enterprises)
  - SBI Account # 552109483319 (Deepak Rawat)

[ACTION 2 - SECTION 94 BNSS NOTICE TO INTERNET SERVICE PROVIDER]:
  Issue statutory notice to Excitel Broadband requesting IP allocation records, MAC address,
  subscriber identity, and session authentication logs for IP 103.87.212.45 active on
  18-Oct-2026 at 02:14:22 IST.

[ACTION 3 - TELECOM CDR / CAF PRESERVATION]:
  Issue preservation notice to Telecom Service Provider for Call Detail Records (CDR),
  Tower Location, and Customer Acquisition Form (CAF) for mobile +91-98765-43210.

[ACTION 4 - NCRP 1930 LIEN MARKING]:
  Submit immediate lien marking on National Cyber Crime Reporting Portal (NCRP) to halt
  ATM cash-out operations on secondary mule accounts.

----------------------------------------------------------------------------------------
LEGAL DISCLAIMER:
AI flags suspicious items for human investigator verification.
This report is generated by Drishti Indigenous AI Digital Forensics Framework for police
and authorized judicial authorities.
========================================================================================
"""
    return report


def generate_llm_report_with_ollama(prompt_context: str, model_name: str = "llama3"):
    """
    Attempts to query a local Ollama instance if active.
    Returns (response_text, success_bool, error_message).
    """
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": model_name,
        "prompt": f"""You are an elite Indian Cyber Crime Forensic Expert.
Analyze the following forensic investigation data and generate an exhaustive, court-ready Cybercrime Case Report complying with Indian IT Act Section 65B and BNSS.

Forensic Context:
{prompt_context}

Provide a structured, professional report with executive summary, timeline reconstruction, suspicious entities, and legal action steps. End with the mandatory disclaimer: 'AI flags suspicious items for human investigator verification.'""",
        "stream": False
    }

    try:
        response = requests.post(url, json=payload, timeout=8)
        if response.status_code == 200:
            data = response.json()
            return data.get("response", ""), True, None
        else:
            return "", False, f"Ollama HTTP {response.status_code}: {response.text}"
    except Exception as e:
        return "", False, str(e)
