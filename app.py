import pandas as pd
import plotly.express as px
import streamlit as st

from pathlib import Path


# ---------------- PAGE CONFIGURATION ----------------

st.set_page_config(
    page_title="Security Log Analyzer",
    page_icon="🛡️",
    layout="wide"
)


# ---------------- CUSTOM DESIGN ----------------

st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: white;
}

[data-testid="stSidebar"] {
    background-color: #111827;
}

div[data-testid="stMetric"] {
    background-color: #172033;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #293548;
}

h1, h2, h3 {
    color: #38bdf8;
}
</style>
""", unsafe_allow_html=True)


# ---------------- HEADER ----------------

st.title("🛡️ Security Log Analyzer")

st.write(
    "Analyze security logs, identify suspicious login activity, "
    "and generate security reports."
)

st.info(
    "This application analyzes supplied log records. "
    "Alerts indicate suspicious patterns and require investigation."
)


# ---------------- SAMPLE DATA ----------------

SAMPLE_PATH = Path("data/sample_security_logs.csv")

REQUIRED_COLUMNS = [
    "timestamp",
    "ip_address",
    "event_type",
    "status",
    "username"
]


def prepare_data(df):
    df.columns = [
        str(column).strip().lower()
        for column in df.columns
    ]

    missing = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            "Missing columns: " + ", ".join(missing)
        )

    df = df[REQUIRED_COLUMNS].copy()

    for column in [
        "ip_address",
        "event_type",
        "status",
        "username"
    ]:
        df[column] = (
            df[column]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    df["event_type"] = df["event_type"].str.lower()
    df["status"] = df["status"].str.lower()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    df = df.dropna(subset=["timestamp"])

    df = df[
        (df["ip_address"] != "")
        & (df["event_type"] != "")
        & (df["status"] != "")
        & (df["username"] != "")
    ].copy()

    if df.empty:
        raise ValueError("No valid log records were found.")

    return df.sort_values("timestamp").reset_index(drop=True)


def analyze_logs(df, threshold, window_minutes):
    logs = df.copy()

    failed_mask = (
        logs["event_type"].eq("login")
        & logs["status"].eq("failed")
    )

    failed_logs = logs[failed_mask].copy()

    suspicious_ips = set()
    alert_records = []

    window_seconds = window_minutes * 60

    for ip, group in failed_logs.groupby("ip_address"):

        group = group.sort_values("timestamp")

        timestamps = group["timestamp"].tolist()
        left = 0

        for right in range(len(timestamps)):

            while (
                left <= right
                and (
                    timestamps[right] - timestamps[left]
                ).total_seconds() > window_seconds
            ):
                left += 1

            attempts = right - left + 1

            if attempts >= threshold:

                suspicious_ips.add(ip)

                alert_records.append({
                    "timestamp": timestamps[right],
                    "ip_address": ip,
                    "failed_attempts": attempts,
                    "severity": (
                        "High"
                        if attempts >= threshold * 2
                        else "Medium"
                    ),
                    "alert": "Repeated failed login attempts"
                })

    logs["severity"] = "Low"
    logs["alert"] = "Normal activity"

    for index, row in logs.iterrows():

        if (
            row["event_type"] == "login"
            and row["status"] == "failed"
        ):

            if row["ip_address"] in suspicious_ips:
                logs.at[index, "severity"] = "High"
                logs.at[index, "alert"] = (
                    "Repeated failed login attempts"
                )
            else:
                logs.at[index, "severity"] = "Medium"
                logs.at[index, "alert"] = "Failed login"

    alerts = pd.DataFrame(alert_records)

    return logs, alerts


# ---------------- SIDEBAR ----------------

st.sidebar.title("⚙️ Settings")

data_source = st.sidebar.radio(
    "Choose data source",
    ["Sample Dataset", "Upload CSV"]
)

threshold = st.sidebar.slider(
    "Failed login threshold",
    min_value=3,
    max_value=15,
    value=5
)

window_minutes = st.sidebar.selectbox(
    "Detection time window",
    [1, 5, 10, 15, 30, 60],
    index=2
)


# ---------------- LOAD DATA ----------------

if data_source == "Sample Dataset":

    if not SAMPLE_PATH.exists():
        st.error(
            "Sample file not found. Create "
            "data/sample_security_logs.csv first."
        )
        st.stop()

    raw_data = pd.read_csv(SAMPLE_PATH)

else:

    uploaded_file = st.sidebar.file_uploader(
        "Upload security log CSV",
        type=["csv"]
    )

    if uploaded_file is None:
        st.info("Upload a CSV file to begin analysis.")

        st.code(
            "timestamp,ip_address,event_type,status,username"
        )

        st.stop()

    try:
        raw_data = pd.read_csv(uploaded_file)

    except Exception as error:
        st.error(f"Could not read CSV: {error}")
        st.stop()


# ---------------- ANALYZE DATA ----------------

try:
    data = prepare_data(raw_data)

    logs, alerts = analyze_logs(
        data,
        threshold,
        window_minutes
    )

except Exception as error:
    st.error(f"Analysis error: {error}")
    st.stop()


# ---------------- DASHBOARD METRICS ----------------

total_events = len(logs)

failed_logins = int(
    (
        logs["event_type"].eq("login")
        & logs["status"].eq("failed")
    ).sum()
)

successful_logins = int(
    (
        logs["event_type"].eq("login")
        & logs["status"].eq("success")
    ).sum()
)

flagged_ips = int(
    logs.loc[
        logs["alert"].eq("Repeated failed login attempts"),
        "ip_address"
    ].nunique()
)

st.subheader("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("Failed Logins", failed_logins)
col3.metric("Successful Logins", successful_logins)
col4.metric("Flagged IPs", flagged_ips)


# ---------------- CHARTS ----------------

st.divider()

st.subheader("📈 Security Analytics")

chart1, chart2 = st.columns(2)

with chart1:

    event_counts = (
        logs["event_type"]
        .value_counts()
        .reset_index()
    )

    event_counts.columns = ["Event", "Count"]

    fig1 = px.pie(
        event_counts,
        names="Event",
        values="Count",
        hole=0.5,
        title="Event Distribution"
    )

    fig1.update_layout(template="plotly_dark")

    st.plotly_chart(fig1, use_container_width=True)


with chart2:

    login_data = logs[
        logs["event_type"].eq("login")
    ]

    if not login_data.empty:

        status_counts = (
            login_data["status"]
            .value_counts()
            .reset_index()
        )

        status_counts.columns = ["Status", "Count"]

        fig2 = px.bar(
            status_counts,
            x="Status",
            y="Count",
            color="Status",
            title="Login Status"
        )

        fig2.update_layout(template="plotly_dark")

        st.plotly_chart(fig2, use_container_width=True)

    else:
        st.info("No login events available.")


# ---------------- ALERTS ----------------

st.divider()

st.subheader("🚨 Security Alerts")

if alerts.empty:

    st.success(
        "No repeated failed-login pattern met the selected threshold."
    )

else:

    st.warning(
        f"{len(alerts)} alert records detected. "
        "Review these records for possible suspicious activity."
    )

    st.dataframe(
        alerts,
        use_container_width=True,
        hide_index=True
    )


# ---------------- LOG TABLE ----------------

st.divider()

st.subheader("📋 Security Event Records")

search_ip = st.text_input(
    "Search by IP address"
)

filtered_logs = logs.copy()

if search_ip.strip():

    filtered_logs = filtered_logs[
        filtered_logs["ip_address"].str.contains(
            search_ip.strip(),
            case=False,
            regex=False
        )
    ]

st.dataframe(
    filtered_logs.sort_values(
        "timestamp",
        ascending=False
    ),
    use_container_width=True,
    hide_index=True
)


# ---------------- DOWNLOAD REPORTS ----------------

st.divider()

st.subheader("📥 Download Reports")

col1, col2 = st.columns(2)

with col1:

    st.download_button(
        "Download Analyzed Logs",
        data=logs.to_csv(index=False).encode("utf-8"),
        file_name="analyzed_security_logs.csv",
        mime="text/csv"
    )

with col2:

    st.download_button(
        "Download Security Alerts",
        data=alerts.to_csv(index=False).encode("utf-8"),
        file_name="security_alerts.csv",
        mime="text/csv"
    )


# ---------------- FOOTER ----------------

st.divider()

st.caption(
    "Security Log Analyzer | Information Systems Security Project"
)