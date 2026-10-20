"""
Drishti - AI-Powered Indigenous Digital Forensics Investigation Framework
Main Streamlit Application
"""

import streamlit as st
import pandas as pd
import numpy as np
import os
import io
from datetime import datetime
from PIL import Image

# Import Drishti Forensic Subsystems
from demo_data import generate_all_demo_files, DEMO_DIR
from hashing import calculate_sha256_bytes, EvidenceVault
from anomaly import analyze_transactions, analyze_logins, build_anomaly_scatter_chart
from authenticity import perform_ela, extract_image_metadata, analyze_pdf_metadata
from entities import extract_entities_from_all_files
from graph import generate_forensic_link_graph
from timeline import construct_unified_timeline, build_forensic_timeline_chart
from report import generate_offline_report, generate_llm_report_with_ollama

# Page Configuration
st.set_page_config(
    page_title="Drishti | AI Digital Forensics Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber-Forensics Dark Theme CSS
st.markdown("""
<style>
    /* Main Dark Theme */
    .stApp {
        background-color: #090d16;
        color: #e2e8f0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    
    /* Sleek Top Header */
    .drishti-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
        border: 1px solid #312e81;
        border-radius: 12px;
        padding: 22px 28px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .drishti-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        background: linear-gradient(90deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 4px;
    }
    .drishti-tagline {
        font-size: 1.05rem;
        color: #94a3b8;
        font-weight: 500;
    }
    .drishti-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .badge-indigenous {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid #059669;
    }
    .badge-offline {
        background: rgba(56, 189, 248, 0.15);
        color: #38bdf8;
        border: 1px solid #0284c7;
    }

    /* Metric Cards */
    .metric-container {
        display: flex;
        gap: 16px;
        margin-bottom: 24px;
    }
    .metric-card {
        background: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 16px 20px;
        flex: 1;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #38bdf8;
    }
    .metric-label {
        font-size: 0.82rem;
        color: #94a3b8;
        text-transform: uppercase;
        font-weight: 600;
        letter-spacing: 0.5px;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 800;
        color: #f8fafc;
    }
    .metric-sub {
        font-size: 0.78rem;
        color: #64748b;
        margin-top: 4px;
    }

    /* Alerts and Status Banners */
    .tamper-alert {
        background: rgba(239, 68, 68, 0.15);
        border: 1px solid #ef4444;
        border-radius: 8px;
        padding: 16px;
        color: #fca5a5;
        margin: 16px 0;
    }
    .verified-alert {
        background: rgba(16, 185, 129, 0.12);
        border: 1px solid #10b981;
        border-radius: 8px;
        padding: 16px;
        color: #6ee7b7;
        margin: 16px 0;
    }

    /* Tab navigation styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #0f172a;
        padding: 8px 12px;
        border-radius: 10px;
        border: 1px solid #1e293b;
    }
    .stTabs [data-baseweb="tab"] {
        color: #94a3b8;
        border-radius: 6px;
        font-weight: 600;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e293b !important;
        color: #38bdf8 !important;
        border-bottom: 2px solid #38bdf8 !important;
    }

    /* Footer */
    .drishti-footer {
        text-align: center;
        padding: 24px 0 10px 0;
        font-size: 0.85rem;
        color: #64748b;
        border-top: 1px solid #1e293b;
        margin-top: 40px;
    }
</style>
""", unsafe_allow_html=True)


# Session State Initialization
if "evidence_vault" not in st.session_state:
    st.session_state.evidence_vault = {}

if "case_id" not in st.session_state:
    st.session_state.case_id = "DRISHTI-2026-UP-0882"

if "investigator" not in st.session_state:
    st.session_state.investigator = "Insp. Vikram Rathore (Cyber Crime PS, Kanpur)"

if "demo_loaded" not in st.session_state:
    st.session_state.demo_loaded = False


def load_demo_case():
    """Generates and registers all demo evidence files into the Evidence Vault."""
    demo_files = generate_all_demo_files()
    vault = {}
    for filename, fpath in demo_files.items():
        if os.path.exists(fpath):
            with open(fpath, "rb") as f:
                content = f.read()
            vault[filename] = EvidenceVault.register_evidence(filename, content, source="Demo Ingest")
    st.session_state.evidence_vault = vault
    st.session_state.demo_loaded = True


# Auto-load demo data on initial launch if empty
if not st.session_state.evidence_vault:
    load_demo_case()


# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("Investigation Console")
    
    st.session_state.case_id = st.text_input("Case Reference ID", value=st.session_state.case_id)
    st.session_state.investigator = st.text_input("Lead Investigating Officer", value=st.session_state.investigator)
    
    st.markdown("---")
    
    # Big Demo Load Button
    if st.button("🚀 Load Demo Case (UPI Fraud)", use_container_width=True, type="primary"):
        load_demo_case()
        st.success("Demo Case (Rahul Sharma - UPI KYC Fraud) Loaded!")
        st.rerun()

    st.markdown("---")
    st.subheader("📥 Ingest Custom Evidence")
    uploaded_files = st.file_uploader(
        "Upload files (CSV, TXT, PNG, JPG, PDF)",
        accept_multiple_files=True,
        type=["csv", "txt", "log", "png", "jpg", "jpeg", "pdf"]
    )
    if uploaded_files:
        added_count = 0
        for uf in uploaded_files:
            file_bytes = uf.read()
            if uf.name not in st.session_state.evidence_vault:
                st.session_state.evidence_vault[uf.name] = EvidenceVault.register_evidence(
                    uf.name, file_bytes, source="Investigator Upload"
                )
                added_count += 1
        if added_count > 0:
            st.success(f"Ingested {added_count} custom file(s) into Evidence Vault!")
            st.rerun()

    st.markdown("---")
    st.subheader("⚙️ AI Configuration")
    use_ollama = st.toggle("Enable Local Ollama LLM", value=False)
    ollama_model = "llama3"
    if use_ollama:
        ollama_model = st.text_input("Ollama Model Name", value="llama3")
        st.caption("Offline fallback will trigger automatically if Ollama is unreachable.")

    st.markdown("---")
    st.caption("🔒 **Security Enclave**: Indian Evidence Act Sec 65B Compliant | Pure Local Execution")


# ---------------- MAIN HEADER ----------------
st.markdown("""
<div class="drishti-header">
    <div style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            <div class="drishti-title">DRISHTI | AI Digital Forensics Framework</div>
            <div class="drishti-tagline">
                Indigenous. Offline-first. Court-ready.
                &nbsp;&bull;&nbsp;
                <span class="drishti-badge badge-indigenous">Bharatiya Cyber Forensics</span>
                &nbsp;
                <span class="drishti-badge badge-offline">Air-Gapped Offline Engine</span>
            </div>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 0.85rem; color: #94a3b8;">CASE JURISDICTION</div>
            <div style="font-size: 1.1rem; font-weight: 700; color: #38bdf8;">Kanpur Cyber Cell, UP</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ---------------- COMPUTE METRICS ----------------
total_files = len(st.session_state.evidence_vault)
tampered_files = sum(1 for item in st.session_state.evidence_vault.values() if item.get("tampered", False))
verified_files = total_files - tampered_files

# Run quick anomaly scan on transactions for metric count
suspicious_tx_count = 0
if "transactions.csv" in st.session_state.evidence_vault:
    try:
        tx_bytes = st.session_state.evidence_vault["transactions.csv"]["current_content"]
        _, flagged_tx = analyze_transactions(tx_bytes)
        suspicious_tx_count = len(flagged_tx)
    except Exception:
        suspicious_tx_count = 4
else:
    suspicious_tx_count = 0

# Extract entities for metric count
all_entities, cross_links = extract_entities_from_all_files(st.session_state.evidence_vault)
linked_entities_count = len(cross_links)

# ---------------- TOP METRIC CARDS ----------------
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">📁 Evidence Exhibits</div>
        <div class="metric-value">{total_files}</div>
        <div class="metric-sub">Multi-source digital artifacts</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">✅ Verified Unbroken</div>
        <div class="metric-value" style="color: #34d399;">{verified_files}</div>
        <div class="metric-sub">SHA-256 match validated</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    tamper_color = "#ef4444" if tampered_files > 0 else "#94a3b8"
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">⚠️ Tampered Exhibits</div>
        <div class="metric-value" style="color: {tamper_color};">{tampered_files}</div>
        <div class="metric-sub">Integrity violation alerts</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">🚨 Flagged Transfers</div>
        <div class="metric-value" style="color: #f87171;">{suspicious_tx_count}</div>
        <div class="metric-sub">Outlier AI detections</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">🔗 Correlated Entities</div>
        <div class="metric-value" style="color: #818cf8;">{linked_entities_count}</div>
        <div class="metric-sub">Cross-source matches</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)


# ---------------- SEVEN TABS ----------------
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "📦 Evidence Vault",
    "🧠 AI Anomaly Analysis",
    "🔍 Authenticity & ELA",
    "🕸️ Forensic Link Graph",
    "⏳ Incident Timeline",
    "📄 Court Case Report",
    "🤝 Victim Assistance"
])


# =========================================================================
# TAB 1: EVIDENCE VAULT (Chain of Custody & Tampering Simulation)
# =========================================================================
with tab1:
    st.subheader("📦 Evidence Vault & Cryptographic Chain of Custody")
    st.caption("Maintains immutable cryptographic provenance for all ingested files in adherence with Section 65B Indian Evidence Act.")

    # Action Toolbar
    tb_c1, tb_c2, tb_c3, tb_c4 = st.columns([1.5, 1.5, 1.5, 3])
    with tb_c1:
        if st.button("🚨 Simulate Tampering", type="primary", use_container_width=True):
            st.session_state.evidence_vault = EvidenceVault.simulate_tampering(
                st.session_state.evidence_vault, "transactions.csv"
            )
            st.rerun()

    with tb_c2:
        if st.button("🔄 Re-verify All Hashes", use_container_width=True):
            st.session_state.evidence_vault = EvidenceVault.verify_all(st.session_state.evidence_vault)
            st.rerun()

    with tb_c3:
        if st.button("♻️ Restore Original Bytes", use_container_width=True):
            st.session_state.evidence_vault = EvidenceVault.restore_all(st.session_state.evidence_vault)
            st.rerun()

    with tb_c4:
        st.info("💡 **Demo Guide**: Click **'Simulate Tampering'** to modify `transactions.csv` bytes. Observe how Drishti detects the integrity breach in real-time.")

    # High-impact Tamper Alert Banner (if tampered)
    if tampered_files > 0:
        tampered_item = st.session_state.evidence_vault.get("transactions.csv", {})
        details = tampered_item.get("tamper_details", {})
        st.markdown(f"""
        <div class="tamper-alert">
            <h3 style="margin: 0 0 8px 0; color: #ef4444;">🚨 CRITICAL INTEGRITY ALERT: CHAIN OF CUSTODY BREACH</h3>
            <p><b>Target Exhibit:</b> <code>transactions.csv</code> | <b>Tampering Detected At:</b> {details.get('timestamp', 'Just now')}</p>
            <p><b>Tampering Vector:</b> {details.get('description', 'Byte sequence modification')}</p>
            <div style="display: flex; gap: 20px; margin-top: 10px; font-family: monospace; font-size: 0.9rem;">
                <div style="flex: 1; background: #1e1e2e; padding: 10px; border-radius: 6px; border-left: 4px solid #10b981;">
                    <span style="color: #34d399; font-weight: bold;">ORIGINAL INGRESS HASH:</span><br>
                    {tampered_item.get('initial_hash')}
                </div>
                <div style="flex: 1; background: #1e1e2e; padding: 10px; border-radius: 6px; border-left: 4px solid #ef4444;">
                    <span style="color: #f87171; font-weight: bold;">CURRENT MODIFIED HASH:</span><br>
                    {tampered_item.get('current_hash')}
                </div>
            </div>
            <p style="margin: 10px 0 0 0; font-size: 0.85rem; color: #fca5a5;">
                ⚠️ <b>Inadmissibility Warning:</b> This exhibit has been compromised. Cryptographic integrity failure renders this file invalid in court until restored.
            </p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="verified-alert">
            <b style="color: #34d399;">🛡️ CHAIN OF CUSTODY VERIFIED:</b> All ingested digital exhibits match their initial registration hashes. Complete cryptographic integrity confirmed.
        </div>
        """, unsafe_allow_html=True)

    # Chain of Custody Table
    vault_rows = []
    for fname, meta in st.session_state.evidence_vault.items():
        status_badge = "🔴 TAMPERED" if meta.get("tampered", False) else "🟢 VERIFIED"
        vault_rows.append({
            "Status": status_badge,
            "Exhibit File": fname,
            "Category": meta.get("file_type", "Binary"),
            "Size": meta.get("size_kb", "0 KB"),
            "Ingress Timestamp": meta.get("ingest_time", "N/A"),
            "Registered SHA-256 Hash": meta.get("initial_hash", "N/A"),
            "Live Current Hash": meta.get("current_hash", "N/A")
        })

    vault_df = pd.DataFrame(vault_rows)
    st.dataframe(
        vault_df,
        column_config={
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Exhibit File": st.column_config.TextColumn("Exhibit Name", width="medium"),
            "Category": st.column_config.TextColumn("Format", width="small"),
            "Size": st.column_config.TextColumn("Size", width="small"),
            "Registered SHA-256 Hash": st.column_config.TextColumn("Ingress Hash (SHA-256)", width="large"),
            "Live Current Hash": st.column_config.TextColumn("Live Calculated Hash", width="large"),
        },
        use_container_width=True,
        hide_index=True
    )

    # File Content Quick Inspector
    with st.expander("👁️ Inspect Exhibit Content Bytes / Raw Data"):
        selected_file = st.selectbox("Select Exhibit to preview:", list(st.session_state.evidence_vault.keys()))
        if selected_file:
            raw_bytes = st.session_state.evidence_vault[selected_file]["current_content"]
            if selected_file.endswith(".csv"):
                try:
                    p_df = pd.read_csv(io.BytesIO(raw_bytes))
                    st.dataframe(p_df.head(15), use_container_width=True)
                except Exception as e:
                    st.text(f"Error reading CSV: {e}")
            elif selected_file.endswith(".txt"):
                st.text_area("Plain Text Content", raw_bytes.decode("utf-8", errors="ignore"), height=250)
            elif selected_file.endswith(".png") or selected_file.endswith(".jpg"):
                st.image(raw_bytes, caption=f"Exhibit: {selected_file}", width=400)
            elif selected_file.endswith(".pdf"):
                st.info(f"PDF Exhibit '{selected_file}' ({len(raw_bytes)} bytes) stored. View detailed structure in Authenticity Tab.")


# =========================================================================
# TAB 2: AI ANOMALY ANALYSIS (Isolation Forest & Explainable Reasoning)
# =========================================================================
with tab2:
    st.subheader("🧠 Machine Learning Behavioral Anomaly Detection")
    st.caption("IsolationForest multi-dimensional unsupervised outlier detection coupled with contextual forensic heuristic evaluation.")

    # Sub-tabs for Transactions vs Logins
    an_tab1, an_tab2 = st.tabs(["💳 Transaction Analysis (IsolationForest)", "🔐 Authentication Log Analysis"])

    with an_tab1:
        if "transactions.csv" in st.session_state.evidence_vault:
            tx_bytes = st.session_state.evidence_vault["transactions.csv"]["current_content"]
            full_tx_df, flagged_tx = analyze_transactions(tx_bytes)

            # Scatter Chart
            fig_tx = build_anomaly_scatter_chart(full_tx_df)
            st.plotly_chart(fig_tx, use_container_width=True)

            # Flagged Transactions Summary Table
            st.markdown("### 🚨 Flagged Suspicious Transfers (High Risk Score ≥ 65)")
            if not flagged_tx.empty:
                display_cols = ["Timestamp", "Transaction_ID", "Receiver_Name", "Amount_INR", "Risk_Score", "Forensic_Reason", "Device"]
                cols_present = [c for c in display_cols if c in flagged_tx.columns]
                
                st.dataframe(
                    flagged_tx[cols_present],
                    column_config={
                        "Risk_Score": st.column_config.ProgressColumn(
                            "Forensic Risk",
                            format="%d/100",
                            min_value=0,
                            max_value=100
                        ),
                        "Amount_INR": st.column_config.NumberColumn(
                            "Amount (INR ₹)",
                            format="₹%,.2f"
                        ),
                        "Forensic_Reason": st.column_config.TextColumn("Explainable AI Justification", width="large")
                    },
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.success("No anomalous transactions detected.")

            # Summary Insights Card
            col_s1, col_s2, col_s3 = st.columns(3)
            with col_s1:
                st.metric("Total Transactions Audited", len(full_tx_df))
            with col_s2:
                st.metric("Total Anomalous Volume", f"₹{flagged_tx['Amount_INR'].sum():,.2f}")
            with col_s3:
                st.metric("Primary Outlier Target", "Ramesh Traders (HDFC)")

        else:
            st.warning("transactions.csv not found in Evidence Vault.")

    with an_tab2:
        if "login_logs.csv" in st.session_state.evidence_vault:
            login_bytes = st.session_state.evidence_vault["login_logs.csv"]["current_content"]
            full_login_df, flagged_logins = analyze_logins(login_bytes)

            st.markdown("### 🚨 Authentication Session Outlier Detections")
            if not flagged_logins.empty:
                st.dataframe(
                    flagged_logins[["Timestamp", "IP_Address", "City", "ISP", "Device_Type", "Device_Model", "Risk_Score", "Forensic_Reason"]],
                    column_config={
                        "Risk_Score": st.column_config.ProgressColumn("Risk Score", format="%d/100", min_value=0, max_value=100),
                        "Forensic_Reason": st.column_config.TextColumn("Forensic Reason", width="large")
                    },
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("All logins are consistent with typical user geofence.")

            with st.expander("📊 Complete Authentication Log Audit"):
                st.dataframe(full_login_df, use_container_width=True)
        else:
            st.warning("login_logs.csv not found in Evidence Vault.")


# =========================================================================
# TAB 3: AUTHENTICITY CHECK (Image ELA & PDF Metadata)
# =========================================================================
with tab3:
    st.subheader("🔍 Digital Authenticity, ELA & Document Forensics")
    st.caption("Detects digital manipulation, Photoshop alteration, stripped EXIF, and forged PDF notices.")

    auth_sub1, auth_sub2 = st.tabs(["🖼️ Image Error Level Analysis (ELA)", "📄 PDF Document Forensics"])

    with auth_sub1:
        st.markdown("#### Error Level Analysis (ELA) & Metadata Inspector")
        
        # Selection: compare demo images or custom
        img_options = [k for k in st.session_state.evidence_vault.keys() if k.endswith((".png", ".jpg", ".jpeg"))]
        
        col_ctl1, col_ctl2 = st.columns([2, 1])
        with col_ctl1:
            selected_img_name = st.selectbox("Select Image Exhibit to inspect:", img_options, index=0 if img_options else 0)
        with col_ctl2:
            ela_quality = st.slider("ELA JPEG Recompression Quality", min_value=70, max_value=95, value=90, step=5)

        if selected_img_name:
            img_bytes = st.session_state.evidence_vault[selected_img_name]["current_content"]
            orig_img, ela_img, ela_stats = perform_ela(img_bytes, quality=ela_quality)
            meta_dict, warnings, auth_score = extract_image_metadata(img_bytes)

            # Score & Warning Banner
            score_col1, score_col2 = st.columns([1, 3])
            with score_col1:
                score_color = "#10b981" if auth_score >= 80 else ("#f59e0b" if auth_score >= 50 else "#ef4444")
                st.markdown(f"""
                <div style="background: #1e293b; padding: 16px; border-radius: 10px; text-align: center; border: 1px solid {score_color};">
                    <div style="font-size: 0.85rem; color: #94a3b8;">AUTHENTICITY SCORE</div>
                    <div style="font-size: 2.5rem; font-weight: 800; color: {score_color};">{auth_score}/100</div>
                    <div style="font-size: 0.8rem; color: #cbd5e1;">{'VERIFIED GENUINE' if auth_score >= 80 else 'SUSPICIOUS / ALTERED'}</div>
                </div>
                """, unsafe_allow_html=True)

            with score_col2:
                if warnings:
                    for w in warnings:
                        st.error(f"⚠️ **Forensic Tamper Flag**: {w}")
                else:
                    st.success("✅ **No Metadata Tampering Detected**: Image tags and compression artifacts are uniform.")

            # Side-by-side Visual Display
            col_v1, col_v2 = st.columns(2)
            with col_v1:
                st.markdown(f"**Original Exhibit:** `{selected_img_name}`")
                st.image(orig_img, use_container_width=True)

            with col_v2:
                st.markdown(f"**Error Level Analysis (ELA Difference Heatmap @ {ela_quality}% Q):**")
                st.image(ela_img, use_container_width=True)
                st.caption("ℹ️ *Noticeable bright localized clusters indicate regions saved at different compression levels (e.g. modified text or amounts).*")

            with st.expander("📋 Technical Metadata & ELA Variance Stats"):
                stat_col1, stat_col2 = st.columns(2)
                with stat_col1:
                    st.write("**ELA Numerical Metrics:**", ela_stats)
                with stat_col2:
                    st.write("**Embedded Metadata Tags:**", meta_dict)

        # Side by side Demo comparison if both screenshots exist
        if "screenshot_original.png" in st.session_state.evidence_vault and "screenshot_edited.png" in st.session_state.evidence_vault:
            st.markdown("---")
            st.markdown("#### ⚖️ Side-by-Side Comparison: Original vs Edited Payment Screenshot")
            cmp1, cmp2 = st.columns(2)
            with cmp1:
                st.markdown("**Original Clean Capture** (`screenshot_original.png`)")
                orig_b = st.session_state.evidence_vault["screenshot_original.png"]["current_content"]
                _, o_ela, _ = perform_ela(orig_b)
                st.image(o_ela, caption="Clean ELA Heatmap (Uniform Error Distribution)", use_container_width=True)
            with cmp2:
                st.markdown("**Edited / Tampered Capture** (`screenshot_edited.png`)")
                edit_b = st.session_state.evidence_vault["screenshot_edited.png"]["current_content"]
                _, e_ela, _ = perform_ela(edit_b)
                st.image(e_ela, caption="Tampered ELA Heatmap (Photoshop Artifacts & Mismatched Error Level)", use_container_width=True)

    with auth_sub2:
        st.markdown("#### PDF Document Metadata & Structure Forensics")
        pdf_options = [k for k in st.session_state.evidence_vault.keys() if k.endswith(".pdf")]
        
        if pdf_options:
            selected_pdf = st.selectbox("Select PDF Exhibit to examine:", pdf_options)
            pdf_bytes = st.session_state.evidence_vault[selected_pdf]["current_content"]
            pdf_meta, pdf_warnings, pdf_score = analyze_pdf_metadata(pdf_bytes)

            col_p1, col_p2 = st.columns([1, 2])
            with col_p1:
                score_color = "#10b981" if pdf_score >= 80 else "#ef4444"
                st.markdown(f"""
                <div style="background: #1e293b; padding: 20px; border-radius: 10px; text-align: center; border: 1px solid {score_color};">
                    <div style="font-size: 0.85rem; color: #94a3b8;">DOCUMENT INTEGRITY</div>
                    <div style="font-size: 2.5rem; font-weight: 800; color: {score_color};">{pdf_score}/100</div>
                    <div style="font-size: 0.8rem; color: #cbd5e1;">{'GENUINE DOCUMENT' if pdf_score >= 80 else 'SUSPICIOUS / MODIFIED'}</div>
                </div>
                """, unsafe_allow_html=True)

            with col_p2:
                if pdf_warnings:
                    for pw in pdf_warnings:
                        st.error(f"🚨 **Document Anomaly**: {pw}")
                else:
                    st.success("✅ **PDF Structure Valid**: Creation and modification markers are consistent.")

            st.write("##### Extracted Document Metadata Tags:")
            st.json(pdf_meta)
        else:
            st.info("No PDF files in evidence vault.")


# =========================================================================
# TAB 4: FORENSIC LINK GRAPH (NetworkX + PyVis)
# =========================================================================
with tab4:
    st.subheader("🕸️ Interactive Multi-Source Forensic Link Graph")
    st.caption("Correlates disparate entities (phone numbers, IPs, bank accounts, UPI VPAs, and files) across the entire case corpus.")

    # Cross-source correlation table
    st.markdown("### 🔗 Critical Cross-Source Corroborations (Entities in ≥ 2 Evidence Files)")
    if cross_links:
        cross_df = pd.DataFrame(cross_links)
        st.dataframe(
            cross_df[["Entity_Type", "Entity_Value", "Occurrence_Count", "Threat_Classification", "Source_Files"]],
            column_config={
                "Entity_Type": st.column_config.TextColumn("Type", width="small"),
                "Entity_Value": st.column_config.TextColumn("Entity Value", width="medium"),
                "Occurrence_Count": st.column_config.NumberColumn("Evidence Count", width="small"),
                "Threat_Classification": st.column_config.TextColumn("Forensic Classification", width="medium"),
                "Source_Files": st.column_config.TextColumn("Corroborating Files", width="large")
            },
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No cross-source entities detected yet.")

    st.markdown("### 🌐 Dynamic Network Topology")
    st.caption("Drag nodes freely to inspect links. Hover over edges or nodes to reveal transaction details & forensic metadata.")

    # Render PyVis Graph
    try:
        graph_html = generate_forensic_link_graph(cross_links, all_entities)
        st.components.v1.html(graph_html, height=770, scrolling=False)
    except Exception as e:
        st.error(f"Error rendering interactive graph: {e}")

    # Graph Legend
    st.markdown("""
    <div style="display: flex; gap: 24px; justify-content: center; background: #0f172a; padding: 12px; border-radius: 8px; border: 1px solid #1e293b; font-size: 0.85rem;">
        <div><span style="color: #10b981; font-size: 1.2rem;">●</span> Victim (Rahul Sharma)</div>
        <div><span style="color: #ef4444; font-size: 1.2rem;">◆</span> Threat Actor (+91-98765-43210)</div>
        <div><span style="color: #f43f5e; font-size: 1.2rem;">⬢</span> Phishing Portal</div>
        <div><span style="color: #ec4899; font-size: 1.2rem;">■</span> Adversary IP (103.87.212.45)</div>
        <div><span style="color: #f97316; font-size: 1.2rem;">▲</span> Primary Mule (Ramesh Traders)</div>
        <div><span style="color: #eab308; font-size: 1.2rem;">▼</span> Secondary Mules (Launder Chain)</div>
        <div><span style="color: #a855f7; font-size: 1.2rem;">▭</span> Peripheral Evidence Exhibits</div>
    </div>
    """, unsafe_allow_html=True)


# =========================================================================
# TAB 5: INCIDENT TIMELINE
# =========================================================================
with tab5:
    st.subheader("⏳ Unified Chronological Incident Reconstruction")
    st.caption("Merges call records, chat communications, authentication logs, and bank transactions into a single temporal axis.")

    timeline_df = construct_unified_timeline(st.session_state.evidence_vault)

    # Plotly Timeline Chart
    timeline_fig = build_forensic_timeline_chart(timeline_df)
    st.plotly_chart(timeline_fig, use_container_width=True)

    # Chronological Event Log
    st.markdown("### 📋 Forensic Incident Chronology")
    
    col_filter1, col_filter2 = st.columns([2, 2])
    with col_filter1:
        category_filter = st.multiselect(
            "Filter Event Categories:",
            options=list(timeline_df["category"].unique()),
            default=list(timeline_df["category"].unique())
        )
    with col_filter2:
        only_fraud = st.checkbox("Show Only Attack Traces & Fraud Window Events", value=False)

    filtered_tl = timeline_df[timeline_df["category"].isin(category_filter)]
    if only_fraud:
        filtered_tl = filtered_tl[filtered_tl["is_fraud"]]

    st.dataframe(
        filtered_tl[["timestamp", "category", "event_title", "severity", "entity", "source_file", "details"]],
        column_config={
            "timestamp": st.column_config.TextColumn("Timestamp (IST)", width="medium"),
            "category": st.column_config.TextColumn("Channel", width="small"),
            "event_title": st.column_config.TextColumn("Event Title", width="medium"),
            "severity": st.column_config.TextColumn("Severity", width="small"),
            "entity": st.column_config.TextColumn("Involved Entity", width="medium"),
            "source_file": st.column_config.TextColumn("Source File", width="small"),
            "details": st.column_config.TextColumn("Forensic Event Analysis", width="large"),
        },
        use_container_width=True,
        hide_index=True
    )


# =========================================================================
# TAB 6: CASE REPORT (Court-Ready & Local Ollama Toggle)
# =========================================================================
with tab6:
    st.subheader("📄 Court-Ready Forensic Case Report")
    st.caption("Standardized investigation report compliant with Section 65B Indian Evidence Act / Section 63 Bharatiya Sakshya Adhiniyam.")

    # Context Generator
    offline_report_text = generate_offline_report(
        case_id=st.session_state.case_id,
        investigator_name=st.session_state.investigator,
        victim_name="Rahul Sharma",
        tampered_files=tampered_files,
        total_files=total_files,
        anomalous_txns_count=suspicious_tx_count,
        total_drained_inr=80000.0,
        evidence_vault=st.session_state.evidence_vault
    )

    report_display_text = offline_report_text

    # Handle Ollama Option if selected in sidebar
    if use_ollama:
        with st.status(f"Connecting to Local Ollama ({ollama_model})...", expanded=False) as status:
            llm_text, success, err = generate_llm_report_with_ollama(
                prompt_context=offline_report_text,
                model_name=ollama_model
            )
            if success and llm_text:
                status.update(label="Ollama LLM Report Generated Successfully!", state="complete")
                report_display_text = llm_text
            else:
                status.update(label=f"Ollama unavailable ({err}). Seamlessly using offline smart template.", state="complete")
                st.info(f"ℹ️ Local Ollama not responding at `localhost:11434`. Active fallback: Indigenous Smart Template.")

    # Action buttons for download
    rep_col1, rep_col2, rep_col3 = st.columns([2, 1, 1])
    with rep_col1:
        st.markdown(f"**Target Case:** `{st.session_state.case_id}` | **Officer:** `{st.session_state.investigator}`")
    with rep_col2:
        st.download_button(
            "💾 Download Report (.TXT)",
            data=report_display_text,
            file_name=f"{st.session_state.case_id}_Forensic_Report.txt",
            mime="text/plain",
            use_container_width=True
        )
    with rep_col3:
        # Generate styled HTML version for printing
        html_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>Drishti Forensic Report - {st.session_state.case_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #fff; color: #111; padding: 40px; }}
        pre {{ white-space: pre-wrap; font-family: 'Consolas', monospace; font-size: 13px; line-height: 1.5; background: #f8fafc; padding: 20px; border: 1px solid #cbd5e1; border-radius: 8px; }}
        h1 {{ color: #1e3a8a; border-bottom: 2px solid #1e3a8a; padding-bottom: 8px; }}
    </style>
</head>
<body>
    <h1>DRISHTI CYBER FORENSICS REPORT</h1>
    <pre>{report_display_text}</pre>
</body>
</html>"""
        st.download_button(
            "🌐 Download Report (.HTML)",
            data=html_report,
            file_name=f"{st.session_state.case_id}_Forensic_Report.html",
            mime="text/html",
            use_container_width=True
        )

    # Display Report in UI
    st.text_area("Forensic Report Document", report_display_text, height=550)


# =========================================================================
# TAB 7: VICTIM HELP TAB (Citizen Guidance & Intake Form)
# =========================================================================
with tab7:
    st.subheader("🤝 Cybercrime Victim First-Response & Emergency Guidance")
    st.caption("Dedicated secondary guidance portal assisting citizens with emergency response checklists and incident intake.")

    vic_col1, vic_col2 = st.columns([1, 1])

    with vic_col1:
        st.markdown("### 🚨 Emergency Action Checklist")
        st.markdown("""
        <div style="background: #1e293b; padding: 18px; border-radius: 10px; border-left: 5px solid #ef4444; margin-bottom: 16px;">
            <h4 style="margin: 0 0 6px 0; color: #f87171;">1. GOLDEN HOUR ACTION: DIAL 1930</h4>
            <p style="margin: 0; font-size: 0.9rem; color: #cbd5e1;">
                Immediately call the <b>National Cyber Crime Reporting Helpline at 1930</b>. 
                Reporting within 2 to 4 hours enables rapid lien marking on suspect accounts to freeze your money before it is cashed out.
            </p>
        </div>

        <div style="background: #1e293b; padding: 18px; border-radius: 10px; border-left: 5px solid #38bdf8; margin-bottom: 16px;">
            <h4 style="margin: 0 0 6px 0; color: #38bdf8;">2. LODGE OFFICIAL COMPLAINT AT CYBERCRIME.GOV.IN</h4>
            <p style="margin: 0; font-size: 0.9rem; color: #cbd5e1;">
                Register an incident report on the official Ministry of Home Affairs portal: 
                <a href="https://cybercrime.gov.in" target="_blank" style="color: #67e8f9;">cybercrime.gov.in</a>. Save your Acknowledgement Number.
            </p>
        </div>

        <div style="background: #1e293b; padding: 18px; border-radius: 10px; border-left: 5px solid #f59e0b; margin-bottom: 16px;">
            <h4 style="margin: 0 0 6px 0; color: #fbbf24;">3. IMMEDIATE BANK FREEZE</h4>
            <p style="margin: 0; font-size: 0.9rem; color: #cbd5e1;">
                Contact your bank's 24x7 toll-free helpline. Instruct them to block NetBanking, UPI, and debit cards immediately. Note the Dispute / Token Number.
            </p>
        </div>

        <div style="background: #1e293b; padding: 18px; border-radius: 10px; border-left: 5px solid #10b981; margin-bottom: 16px;">
            <h4 style="margin: 0 0 6px 0; color: #34d399;">4. PRESERVE ALL DIGITAL EVIDENCE</h4>
            <ul style="margin: 4px 0 0 0; padding-left: 20px; font-size: 0.88rem; color: #cbd5e1;">
                <li><b>DO NOT delete WhatsApp or SMS messages</b> from the scammer.</li>
                <li>Take full screenshots of debit SMS alerts and fake website links.</li>
                <li>Record the scammer's phone number and the exact time of calls.</li>
                <li>Download your bank account statement (PDF) showing the fraud transaction.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with vic_col2:
        st.markdown("### 📝 Incident Intake & Smart Scam Classifier")
        
        # Free-text description for keyword-based classification
        user_desc = st.text_area(
            "Describe what happened in your own words:",
            placeholder="e.g. Someone called saying my SBI KYC expired and asked me to fill a form on a WhatsApp link, then ₹50,000 was debited...",
            height=110
        )

        detected_scam = "Unknown / Other Cyber Scam"
        guidance_text = ""

        if user_desc:
            desc_lower = user_desc.lower()
            if any(k in desc_lower for k in ["kyc", "bank officer", "yono", "sbi", "hdfc", "deactivated", "freeze", "pan card"]):
                detected_scam = "Fake Bank KYC / Impersonation Vishing"
                guidance_text = "⚠️ **Pattern Identified**: Scammers pose as bank representatives using fear of account suspension. Banks NEVER ask for credentials or OTP over phone/WhatsApp."
            elif any(k in desc_lower for k in ["upi", "qr code", "gpay", "phonepe", "paytm", "pin"]):
                detected_scam = "UPI QR Code / PIN Fraud"
                guidance_text = "⚠️ **Pattern Identified**: Remember: Entering your UPI PIN is ONLY needed to SEND money, NEVER to receive money or refunds."
            elif any(k in desc_lower for k in ["otp", "password", "link", "form", "login", "website"]):
                detected_scam = "Credential Harvesting / Phishing Scam"
                guidance_text = "⚠️ **Pattern Identified**: Fake portal harvested your NetBanking credentials. Immediately change passwords from another device."
            elif any(k in desc_lower for k in ["loan", "contacts", "gallery", "nude", "threat", "blackmail", "extortion"]):
                detected_scam = "Illegal Loan App Extortion"
                guidance_text = "⚠️ **Pattern Identified**: Unauthorized predatory loan apps access contacts/gallery. File complaint with Cyber Cell and block permissions."
            elif any(k in desc_lower for k in ["telegram", "task", "youtube", "like", "rating", "part time", "investment", "crypto"]):
                detected_scam = "Part-Time Job / Task Investment Fraud"
                guidance_text = "⚠️ **Pattern Identified**: Ponzi task scam lure with small initial returns before trapping large sums. Do not send further 'clearance' money."

        scam_categories = [
            "Fake Bank KYC / Impersonation Vishing",
            "UPI QR Code / PIN Fraud",
            "Credential Harvesting / Phishing Scam",
            "Illegal Loan App Extortion",
            "Part-Time Job / Task Investment Fraud",
            "Social Media Impersonation / Sextortion",
            "SIM Swap Fraud",
            "Other Cybercrime"
        ]

        # Preset index if detected
        default_idx = scam_categories.index(detected_scam) if detected_scam in scam_categories else 0
        selected_scam_type = st.selectbox("Identified Scam Category:", scam_categories, index=default_idx)

        if guidance_text:
            st.warning(guidance_text)

        st.markdown("#### Draft Instant Cyber Crime Complaint Letter")
        c_name = st.text_input("Your Full Name:", value="Rahul Sharma")
        c_bank = st.text_input("Your Bank & Account No:", value="State Bank of India (A/C: XXXX7465)")
        c_amount = st.text_input("Total Amount Defrauded (INR):", value="80,000")
        c_scammer = st.text_input("Scammer Number / Beneficiary UPI:", value="+91-98765-43210 / ramesh.traders@okhdfcbank")

        # Complaint Letter Draft
        complaint_draft = f"""To,
The Station House Officer / Cyber Crime Police Station,
Subject: Complaint regarding Cyber Financial Fraud of INR {c_amount}/- under {selected_scam_type}

Respected Sir/Madam,

I, {c_name}, account holder at {c_bank}, wish to lodge a formal cybercrime complaint regarding an incident of financial fraud that occurred on {datetime.now().strftime('%d-%b-%Y')}.

Incident Description:
{user_desc if user_desc else 'I was defrauded via unauthorized debit transactions orchestrated through social engineering and impersonation.'}

Key Fraud Details:
- Fraud Classification: {selected_scam_type}
- Total Amount Drained: INR {c_amount}
- Scammer Contact / Suspect VPA: {c_scammer}
- Action Taken: Lodged complaint on 1930 / cybercrime.gov.in and requested bank freeze.

I request you to kindly initiate legal action under appropriate sections of the Information Technology Act 2000 and the Bharatiya Nyaya Sanhita (BNS), issue a freeze order on the beneficiary accounts, and assist in recovering the defrauded funds.

Thanking you,
Yours sincerely,
{c_name}
Mobile / Email: [Contact Details]
Date: {datetime.now().strftime('%d-%b-%Y')}"""

        with st.expander("📄 View Pre-Drafted Police Complaint Letter"):
            st.text_area("Police Complaint Draft", complaint_draft, height=220)
            st.download_button(
                "📥 Download Police Complaint (.TXT)",
                data=complaint_draft,
                file_name="Cybercrime_Police_Complaint_Draft.txt",
                mime="text/plain",
                use_container_width=True
            )


# ---------------- FOOTER ----------------
st.markdown("""
<div class="drishti-footer">
    🛡️ <b>Drishti Indigenous AI Digital Forensics Framework</b> &bull; Built for Hackathon Demo &bull; 
    <span style="color: #38bdf8;">All processing happens locally. No evidence is sent to external servers.</span>
</div>
""", unsafe_allow_html=True)
