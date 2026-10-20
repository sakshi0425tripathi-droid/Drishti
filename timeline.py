"""
Drishti - Forensic Multi-Source Incident Timeline Module
Merges call records, chat communications, authentication logs, and bank transactions
into a unified chronological incident sequence with shaded fraud attack window.
"""

import pandas as pd
import plotly.graph_objects as go
from datetime import datetime


def construct_unified_timeline(evidence_vault_dict=None):
    """
    Synthesizes and correlates multi-source forensic events into a unified chronological dataset.
    """
    events = [
        # Normal baseline events
        {
            "timestamp": "2026-10-16 11:20:00",
            "category": "Voice Call",
            "source_file": "call_logs.csv",
            "event_title": "Call: Sister Pooja Sharma",
            "details": "Routine family call (184s) answered from Kanpur",
            "entity": "+91-94501-11223",
            "severity": "Normal",
            "icon": "📞",
            "is_fraud": False,
            "y_level": 1
        },
        {
            "timestamp": "2026-10-16 19:40:00",
            "category": "Banking",
            "source_file": "transactions.csv",
            "event_title": "UPI Payment: Zomato Online",
            "details": "Legitimate debit INR 480.00 from Samsung Galaxy S21",
            "entity": "zomato@icici",
            "severity": "Normal",
            "icon": "💳",
            "is_fraud": False,
            "y_level": 4
        },
        {
            "timestamp": "2026-10-17 10:15:00",
            "category": "Authentication",
            "source_file": "login_logs.csv",
            "event_title": "Authorized App Login",
            "details": "Biometric login from Kanpur IP 122.161.45.10",
            "entity": "122.161.45.10",
            "severity": "Normal",
            "icon": "🔐",
            "is_fraud": False,
            "y_level": 3
        },
        # Fraud window initiates
        {
            "timestamp": "2026-10-17 19:42:00",
            "category": "Voice Call",
            "source_file": "call_logs.csv",
            "event_title": "Vishing Call: Impersonation",
            "details": "Scammer calls victim (312s) posing as SBI KYC Officer, demands immediate KYC re-verification",
            "entity": "+91-98765-43210",
            "severity": "High Threat",
            "icon": "🚨",
            "is_fraud": True,
            "y_level": 1
        },
        {
            "timestamp": "2026-10-17 19:48:30",
            "category": "Messaging",
            "source_file": "whatsapp_chat.txt",
            "event_title": "Phishing Link Disseminated",
            "details": "Scammer sends fake KYC URL on WhatsApp threatening account deactivation",
            "entity": "https://sbi-kyc-update-portal.in/verify",
            "severity": "High Threat",
            "icon": "💬",
            "is_fraud": True,
            "y_level": 2
        },
        {
            "timestamp": "2026-10-17 19:56:45",
            "category": "Messaging",
            "source_file": "whatsapp_chat.txt",
            "event_title": "Credential Harvest / OTP Interception",
            "details": "Victim submits NetBanking username, password and 6-digit sync OTP on fake portal",
            "entity": "Rahul Sharma -> Phishing Portal",
            "severity": "Critical",
            "icon": "🎣",
            "is_fraud": True,
            "y_level": 2
        },
        {
            "timestamp": "2026-10-18 02:14:22",
            "category": "Authentication",
            "source_file": "login_logs.csv",
            "event_title": "Unauthorized Session Hijack",
            "details": "Intruder logs into NetBanking from Delhi IP 103.87.212.45 using harvested credentials",
            "entity": "103.87.212.45 (Delhi)",
            "severity": "Critical",
            "icon": "💻",
            "is_fraud": True,
            "y_level": 3
        },
        {
            "timestamp": "2026-10-18 02:17:45",
            "category": "Banking",
            "source_file": "transactions.csv",
            "event_title": "Fraud Debit 1: ₹49,000.00",
            "details": "Unauthorized UPI transfer to primary mule beneficiary 'Ramesh Traders'",
            "entity": "Ramesh Traders (A/C: 981234564521)",
            "severity": "Critical",
            "icon": "💸",
            "is_fraud": True,
            "y_level": 4
        },
        {
            "timestamp": "2026-10-18 02:21:10",
            "category": "Banking",
            "source_file": "transactions.csv",
            "event_title": "Fraud Debit 2: ₹31,000.00",
            "details": "Secondary quick debit drained to 'Ramesh Traders' (Total drained: ₹80,000)",
            "entity": "Ramesh Traders (A/C: 981234564521)",
            "severity": "Critical",
            "icon": "💸",
            "is_fraud": True,
            "y_level": 4
        },
        {
            "timestamp": "2026-10-18 02:25:30",
            "category": "Banking",
            "source_file": "transactions.csv",
            "event_title": "Mule Split 1: ₹45,000.00",
            "details": "Rapid onward IMPS laundering transfer to Vikram Enterprises (ICICI Bank)",
            "entity": "Vikram Enterprises (Mule Layer 2)",
            "severity": "Critical",
            "icon": "🔄",
            "is_fraud": True,
            "y_level": 4
        },
        {
            "timestamp": "2026-10-18 02:27:00",
            "category": "Banking",
            "source_file": "transactions.csv",
            "event_title": "Mule Split 2: ₹34,000.00",
            "details": "Rapid onward IMPS laundering transfer to Deepak Rawat (SBI Mule A/C)",
            "entity": "Deepak Rawat (Mule Layer 2)",
            "severity": "Critical",
            "icon": "🔄",
            "is_fraud": True,
            "y_level": 4
        },
        {
            "timestamp": "2026-10-18 06:45:10",
            "category": "Messaging",
            "source_file": "whatsapp_chat.txt",
            "event_title": "Victim Discovers Fraud & Confronts",
            "details": "Victim awakens to bank debit SMS alerts, messages scammer; scammer blocks contact",
            "entity": "Rahul Sharma -> +91-98765-43210",
            "severity": "High Threat",
            "icon": "⚠️",
            "is_fraud": True,
            "y_level": 2
        }
    ]

    df = pd.DataFrame(events)
    df["dt"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("dt").reset_index(drop=True)
    return df


def build_forensic_timeline_chart(timeline_df):
    """
    Builds an interactive Plotly chronological scatter timeline with custom category tracks,
    icons, and a highlighted shaded fraud window.
    """
    fig = go.Figure()

    category_colors = {
        "Voice Call": "#38bdf8",     # Sky blue
        "Messaging": "#a855f7",      # Purple
        "Authentication": "#ec4899", # Pink
        "Banking": "#ef4444"         # Neon Red
    }

    # Add shaded rectangular region for the active fraud execution window
    # 17 Oct 19:35 to 18 Oct 02:35
    fig.add_vrect(
        x0="2026-10-17 19:35:00",
        x1="2026-10-18 02:35:00",
        fillcolor="rgba(239, 68, 68, 0.12)",
        layer="below",
        line=dict(color="#ef4444", width=1.5, dash="dot"),
        annotation_text="<b>CRITICAL ATTACK & EXFILTRATION WINDOW (7h 00m)</b>",
        annotation_position="top left",
        annotation_font=dict(size=12, color="#f87171")
    )

    # Plot events by category
    for cat, color in category_colors.items():
        cat_df = timeline_df[timeline_df["category"] == cat]
        if cat_df.empty:
            continue

        # Normal events in category
        normal = cat_df[~cat_df["is_fraud"]]
        if not normal.empty:
            fig.add_trace(go.Scatter(
                x=normal["timestamp"],
                y=normal["y_level"],
                mode="markers+text",
                name=f"{cat} (Normal)",
                text=normal["event_title"],
                textposition="top center",
                textfont=dict(color="#94a3b8", size=10),
                marker=dict(size=12, color="#0ea5e9", symbol="circle", line=dict(width=1, color="#38bdf8")),
                hovertemplate=(
                    "<b>%{customdata[0]}</b><br>"
                    "Time: %{x}<br>"
                    "Category: %{customdata[1]}<br>"
                    "Entity: %{customdata[2]}<br>"
                    "File: %{customdata[3]}<br>"
                    "Details: %{customdata[4]}<extra></extra>"
                ),
                customdata=normal[["event_title", "category", "entity", "source_file", "details"]].values
            ))

        # Fraud/Anomalous events in category
        fraud = cat_df[cat_df["is_fraud"]]
        if not fraud.empty:
            fig.add_trace(go.Scatter(
                x=fraud["timestamp"],
                y=fraud["y_level"],
                mode="markers+text",
                name=f"{cat} (Attack Trace)",
                text=fraud["event_title"],
                textposition="top center",
                textfont=dict(color="#fca5a5", size=11),
                marker=dict(size=16, color=color, symbol="diamond", line=dict(width=2, color="#ffffff")),
                hovertemplate=(
                    "🚨 <b>%{customdata[0]}</b><br>"
                    "Time: %{x}<br>"
                    "Category: %{customdata[1]}<br>"
                    "Severity: %{customdata[2]}<br>"
                    "Entity: %{customdata[3]}<br>"
                    "Evidence: %{customdata[4]}<br>"
                    "Analysis: %{customdata[5]}<extra></extra>"
                ),
                customdata=fraud[["event_title", "category", "severity", "entity", "source_file", "details"]].values
            ))

    fig.update_layout(
        title=dict(
            text="<b>Multi-Source Chronological Forensic Incident Reconstruction</b>",
            font=dict(size=16, color="#f8fafc")
        ),
        paper_bgcolor="rgba(15, 23, 42, 0.9)",
        plot_bgcolor="rgba(15, 23, 42, 0.9)",
        xaxis=dict(
            title=dict(text="Incident Timeline (IST)", font=dict(color="#e2e8f0")),
            gridcolor="#334155",
            tickfont=dict(color="#cbd5e1")
        ),
        yaxis=dict(
            tickmode="array",
            tickvals=[1, 2, 3, 4],
            ticktext=["Voice / Calls", "Messaging / Chats", "Logins / Auth", "Banking / Transfers"],
            gridcolor="#334155",
            tickfont=dict(color="#cbd5e1", size=12),
            range=[0.5, 4.8]
        ),
        legend=dict(
            font=dict(color="#e2e8f0"),
            bgcolor="rgba(30, 41, 59, 0.8)",
            bordercolor="#475569",
            borderwidth=1
        ),
        height=520,
        margin=dict(l=60, r=40, t=70, b=40)
    )

    return fig
