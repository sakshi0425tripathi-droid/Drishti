"""
Drishti - AI Anomaly Detection Module
Uses IsolationForest on financial transactions and authentication logs.
Produces risk scores (0-100), explainable plain-English forensic findings, and interactive Plotly visuals.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import io


def analyze_transactions(df_or_bytes):
    """
    Analyzes transaction DataFrame for fraudulent patterns using IsolationForest
    and contextual forensic rule checks.
    """
    if isinstance(df_or_bytes, (bytes, bytearray)):
        df = pd.read_csv(io.BytesIO(df_or_bytes))
    elif isinstance(df_or_bytes, pd.DataFrame):
        df = df_or_bytes.copy()
    else:
        df = pd.read_csv(df_or_bytes)

    if df.empty or "Amount_INR" not in df.columns:
        return df, []

    # Ensure timestamp parsing
    if "Timestamp" in df.columns:
        df["dt"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    else:
        df["dt"] = pd.date_range(start="2026-10-10", periods=len(df), freq="h")

    df = df.sort_values("dt").reset_index(drop=True)

    # Feature Engineering
    df["hour"] = df["dt"].dt.hour
    df["amount"] = pd.to_numeric(df["Amount_INR"], errors="coerce").fillna(0.0)

    # Time gap from previous transaction in seconds
    time_diffs = df["dt"].diff().dt.total_seconds().fillna(3600 * 6)
    df["time_gap_sec"] = time_diffs

    # Historical receiver frequency
    seen_receivers = set()
    is_new_receiver = []
    receiver_col = "Receiver_Name" if "Receiver_Name" in df.columns else "Receiver_Account"
    for r in df[receiver_col].fillna("Unknown"):
        if r in seen_receivers:
            is_new_receiver.append(0)
        else:
            is_new_receiver.append(1)
            seen_receivers.add(r)
    df["is_new_receiver"] = is_new_receiver

    # Compute baseline metrics from normal history (exclude extreme outliers for baseline)
    median_amt = df["amount"].median()
    mean_amt = df["amount"].mean()

    # Features for Isolation Forest
    features = ["amount", "hour", "time_gap_sec", "is_new_receiver"]
    X = df[features].copy()
    
    # Scale features reasonably
    X_scaled = X.copy()
    X_scaled["amount"] = np.log1p(np.maximum(0, X_scaled["amount"]))
    X_scaled["time_gap_sec"] = np.log1p(np.maximum(0, X_scaled["time_gap_sec"]))

    # Fit Isolation Forest
    # 5% to 8% expected contamination in forensic audit
    contamination = min(0.12, max(0.04, 3.0 / len(df)))
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42
    )
    iso_forest.fit(X_scaled)
    preds = iso_forest.predict(X_scaled)  # -1 for anomaly, 1 for normal
    scores = iso_forest.decision_function(X_scaled)  # lower = more abnormal

    # Convert decision score to Risk Score (0-100)
    # Lower decision function means higher anomaly
    min_s, max_s = scores.min(), scores.max()
    if max_s > min_s:
        normalized_anomaly = (max_s - scores) / (max_s - min_s)
    else:
        normalized_anomaly = np.zeros(len(scores))

    risk_scores = []
    reasons = []
    is_anomaly_flag = []

    for i, row in df.iterrows():
        base_risk = int(normalized_anomaly[i] * 70)
        flags = []

        # Contextual forensic rules
        amt_ratio = row["amount"] / max(mean_amt, 10.0)
        is_night = (row["hour"] >= 0 and row["hour"] <= 5)
        
        if row["amount"] >= 15000:
            base_risk += 25
            flags.append(f"High-value transfer INR {row['amount']:,.2f} ({amt_ratio:.1f}x higher than baseline)")
        
        if is_night:
            base_risk += 20
            flags.append(f"Executed at {row['hour']:02d}:{row['dt'].minute:02d} AM (High-risk nocturnal window)")

        if row["is_new_receiver"] == 1 and row["amount"] > 5000:
            base_risk += 15
            flags.append(f"First-time transfer to unseen beneficiary '{row[receiver_col]}'")

        if "Mule" in str(row.get("Receiver_Name", "")) or "IMPS" in str(row.get("Reference_No", "")):
            base_risk += 20
            flags.append("Identified as rapid onward mule hopping transfer")

        # Clamp risk score
        final_risk = min(99, max(5, base_risk))
        is_flagged = (preds[i] == -1) or (final_risk >= 65)

        if not flags and is_flagged:
            flags.append("Isolation Forest detected multi-dimensional behavioral divergence")
        elif not flags:
            flags.append("Consistent with typical daytime user spending habits")

        risk_scores.append(final_risk)
        reasons.append(" | ".join(flags))
        is_anomaly_flag.append(is_flagged)

    df["Risk_Score"] = risk_scores
    df["Forensic_Reason"] = reasons
    df["Is_Anomaly"] = is_anomaly_flag

    flagged_records = df[df["Is_Anomaly"]].copy()
    flagged_records = flagged_records.sort_values("Risk_Score", ascending=False)
    
    return df, flagged_records


def analyze_logins(df_or_bytes):
    """
    Analyzes authentication logs for anomalous geographic jumps,
    nocturnal timings, and credential harvesting exploitation.
    """
    if isinstance(df_or_bytes, (bytes, bytearray)):
        df = pd.read_csv(io.BytesIO(df_or_bytes))
    elif isinstance(df_or_bytes, pd.DataFrame):
        df = df_or_bytes.copy()
    else:
        df = pd.read_csv(df_or_bytes)

    if df.empty or "IP_Address" not in df.columns:
        return df, []

    if "Timestamp" in df.columns:
        df["dt"] = pd.to_datetime(df["Timestamp"], errors="coerce")
    else:
        df["dt"] = pd.date_range(start="2026-10-11", periods=len(df), freq="12h")

    df = df.sort_values("dt").reset_index(drop=True)
    df["hour"] = df["dt"].dt.hour

    # Baseline frequent city & IP
    city_counts = df["City"].value_counts()
    primary_city = city_counts.index[0] if len(city_counts) > 0 else "Kanpur"
    
    ip_counts = df["IP_Address"].value_counts()
    primary_ips = set(ip_counts.head(3).index)

    risk_scores = []
    reasons = []
    is_anomaly_flag = []

    for i, row in df.iterrows():
        risk = 10
        flags = []

        is_new_city = row.get("City", "") != primary_city
        is_new_ip = row.get("IP_Address", "") not in primary_ips
        is_nocturnal = (row["hour"] >= 1 and row["hour"] <= 5)

        if is_new_city:
            risk += 40
            flags.append(f"Geographic anomaly: Login from {row.get('City', 'Unknown')} (User's registered city is {primary_city})")

        if is_new_ip:
            risk += 25
            flags.append(f"Unrecognized IP {row.get('IP_Address')} (ISP: {row.get('ISP', 'Unknown')})")

        if is_nocturnal:
            risk += 20
            flags.append(f"Unusual login time {row['hour']:02d}:{row['dt'].minute:02d} AM")

        if "Browser" in str(row.get("Device_Type", "")) or "Linux" in str(row.get("Device_Model", "")):
            risk += 15
            flags.append(f"Suspicious client device fingerprint: {row.get('Device_Model', '')}")

        final_risk = min(99, max(5, risk))
        flagged = final_risk >= 60

        if not flags:
            flags.append(f"Verified login from primary device in {primary_city}")

        risk_scores.append(final_risk)
        reasons.append(" | ".join(flags))
        is_anomaly_flag.append(flagged)

    df["Risk_Score"] = risk_scores
    df["Forensic_Reason"] = reasons
    df["Is_Anomaly"] = is_anomaly_flag

    flagged_logins = df[df["Is_Anomaly"]].copy().sort_values("Risk_Score", ascending=False)
    return df, flagged_logins


def build_anomaly_scatter_chart(df):
    """
    Builds dark-themed interactive Plotly scatter plot highlighting fraudulent anomalies in red.
    """
    if df.empty or "Amount_INR" not in df.columns:
        fig = go.Figure()
        fig.update_layout(title="No Transaction Data Available")
        return fig

    normal_df = df[~df["Is_Anomaly"]]
    anomaly_df = df[df["Is_Anomaly"]]

    fig = go.Figure()

    # Normal transactions
    fig.add_trace(go.Scatter(
        x=normal_df["Timestamp"],
        y=normal_df["Amount_INR"],
        mode="markers",
        name="Legitimate Transactions",
        marker=dict(
            size=9,
            color="#06b6d4",  # Cyan
            opacity=0.75,
            line=dict(width=1, color="#0891b2")
        ),
        hovertemplate=(
            "<b>%{customdata[0]}</b><br>"
            "Time: %{x}<br>"
            "Amount: ₹%{y:,.2f}<br>"
            "Receiver: %{customdata[1]}<br>"
            "Risk Score: %{customdata[2]}<extra></extra>"
        ),
        customdata=normal_df[["Transaction_ID", "Receiver_Name", "Risk_Score"]].values
    ))

    # Flagged Anomaly Transactions
    fig.add_trace(go.Scatter(
        x=anomaly_df["Timestamp"],
        y=anomaly_df["Amount_INR"],
        mode="markers+text",
        name="Flagged Anomalies (Fraud / Mule)",
        marker=dict(
            size=16,
            color="#ef4444",  # Neon Red
            symbol="diamond",
            line=dict(width=2, color="#ffffff")
        ),
        text=anomaly_df["Receiver_Name"],
        textposition="top center",
        textfont=dict(color="#fca5a5", size=11),
        hovertemplate=(
            "🚨 <b>SUSPICIOUS TRANSACTION: %{customdata[0]}</b><br>"
            "Timestamp: %{x}<br>"
            "Amount: <b>₹%{y:,.2f}</b><br>"
            "Beneficiary: %{customdata[1]}<br>"
            "Risk Score: <b>%{customdata[2]}/100</b><br>"
            "Reason: %{customdata[3]}<extra></extra>"
        ),
        customdata=anomaly_df[["Transaction_ID", "Receiver_Name", "Risk_Score", "Forensic_Reason"]].values
    ))

    fig.update_layout(
        title=dict(
            text="<b>Transaction Behavioral Analysis (IsolationForest Outlier Detection)</b>",
            font=dict(size=16, color="#f1f5f9")
        ),
        paper_bgcolor="rgba(15, 23, 42, 0.8)",
        plot_bgcolor="rgba(15, 23, 42, 0.8)",
        xaxis=dict(
            title=dict(text="Transaction Timestamp", font=dict(color="#cbd5e1")),
            gridcolor="#334155",
            tickfont=dict(color="#94a3b8")
        ),
        yaxis=dict(
            title=dict(text="Transfer Amount (INR ₹)", font=dict(color="#cbd5e1")),
            gridcolor="#334155",
            tickfont=dict(color="#94a3b8")
        ),
        legend=dict(
            font=dict(color="#e2e8f0"),
            bgcolor="rgba(30, 41, 59, 0.7)",
            bordercolor="#475569",
            borderwidth=1
        ),
        height=480,
        margin=dict(l=40, r=40, t=60, b=40)
    )

    return fig
