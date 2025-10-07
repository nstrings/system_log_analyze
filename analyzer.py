import re
import argparse
from collections import Counter
import sys, gzip, datetime as dt

SEVERITY_RE = re.compile(
    r'\b(error|warn|warning|crit|critical|fail|fatal)\b|<(Error|Warning|Notice|Critical|Fatal)>',
    re.IGNORECASE
)

IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')

def normalize_severity(s):
    s = (s or '').lower()
    if s.startswith('warn'): return 'warning'
    if s.startswith('crit'): return 'critical'
    if s in {'fatal','error','fail','notice'}: return s
    return s or 'notice'

def strip_prefix(msg):
    return re.sub(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[^\:]+:\s*', '', msg).strip()

TS_SYSLOG = re.compile(r'^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})')
TS_ISO    = re.compile(r'^(?P<iso>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)')

MON_MAP = {m:i for i,m in enumerate(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'],1)}

def parse_line_ts(line):
    m = TS_ISO.match(line)
    if m:
        s = m.group('iso').replace('T',' ')
        try:
            return dt.datetime.fromisoformat(s)
        except Exception:
            pass
    m = TS_SYSLOG.match(line)
    if m:
        now = dt.datetime.now()
        mon = MON_MAP.get(m.group('mon'), now.month)
        day = int(m.group('day'))
        hh,mm,ss = map(int, m.group('time').split(':'))
        # assume current year
        try:
            return dt.datetime(now.year, mon, day, hh, mm, ss)
        except Exception:
            return None
    return None

PROC_RE = re.compile(r'^\S+(?:\s+\d{1,2})?\s+\d{2}:\d{2}:\d{2}\s+[^\s]+\s+([A-Za-z0-9._-]+)(?:\[\d+\])?:\s')
def extract_proc(line):
    m = PROC_RE.match(line)
    if m:
        return m.group(1)
    # Try generic "proc[pid]:" anywhere
    m = re.search(r'([A-Za-z0-9._-]+)(?:\[\d+\])?:\s', line)
    return m.group(1) if m else None

#
# --- Helpers: relative time parsing and redaction ---
REL_RE = re.compile(r'^\s*(\d+)\s*([mhd])\s*$', re.IGNORECASE)
def parse_relative(spec: str):
    """
    Return an absolute datetime from a relative spec like '15m', '2h', '1d'.
    """
    if not spec:
        return None
    m = REL_RE.match(spec)
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2).lower()
    now = dt.datetime.now()
    if unit == 'm':
        return now - dt.timedelta(minutes=n)
    if unit == 'h':
        return now - dt.timedelta(hours=n)
    if unit == 'd':
        return now - dt.timedelta(days=n)
    return None

RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
RE_HOST  = re.compile(r'\b([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b')
def redact_text(s: str):
    """
    Redact potentially sensitive data in free-text messages.
    (Emails and hostnames). We intentionally do NOT redact IPs here, since
    they are counted separately and often necessary for triage.
    """
    s = RE_EMAIL.sub('[EMAIL]', s)
    s = RE_HOST.sub('[HOST]', s)
    return s

# --- Built-in sidebar presets (optional quick filters) ---
PRESETS = {
    "Errors only": {
        "grep": r"(error|critical|fatal|fail)",
        "exclude": r""
    },
    "Networking (less noise)": {
        "grep": r"(dns|network|tcp|udp|en\d|wifi|airportd|configd|timeout|refused|unreachable|fail|error)",
        "exclude": r"(mdns|bonjour)"
    },
    "Security/Permissions": {
        "grep": r"(denied|sandbox|permission|codesign|authorization|keychain|opendirectoryd|entitlement|policy)",
        "exclude": r""
    },
    "Bluetooth/Peripherals": {
        "grep": r"(bluetoothd|HID|USB|IOBluetooth|disconnect|timeout|peripheral)",
        "exclude": r"(WindowServer.*digitizer)"
    },
    "Power/Battery": {
        "grep": r"(Battery|powerd|Time to Empty|PowerSource|sleep|wake|thermal|throttl)",
        "exclude": r"(displayState)"
    },
    "Windows Events": {
        "grep": r"(Error|Critical|Warning|Information|Schannel|Service Control Manager|DNS Client Events|EventLog|GroupPolicy|User Profile|Security-SPP|AppModel-Runtime|DistributedCOM|MSI Installer)",
        "exclude": r""
    },
    "Windows - DNS Issues": {
        "grep": r"(DNS Client Events|NameResolution|timeout|unreachable|refused|denied)",
        "exclude": r""
    },
    "Windows - Service Failures": {
        "grep": r"(Service Control Manager|service.*failed|could not start)",
        "exclude": r""
    },
    "Windows - TLS/SSL/Schannel": {
        "grep": r"(Schannel|TLS|certificate|trust)",
        "exclude": r""
    },
    "Windows - GPO/User Profile": {
        "grep": r"(GroupPolicy|User Profile|user profile service|roaming profile)",
        "exclude": r""
    },

    # --- macOS focused sub-presets ---
    "macOS - Wi-Fi/DNS": {
        "grep": r"(airportd|wifi|Wi-Fi|en\d|DHCP|DNS|mDNSResponder|configd|reachability|timeout|refused|unreachable)",
        "exclude": r"(bonjour)"
    },
    "macOS - Power/Sleep": {
        "grep": r"(powerd|sleep|darkwake|wake|suspend|resume|thermal|battery|PowerSource|hibernat)",
        "exclude": r""
    },
    "macOS - Sandbox/Permissions": {
        "grep": r"(sandbox|denied|permission|codesign|entitlement|TCC|keychain|privacy|camera|microphone)",
        "exclude": r""
    },
    "macOS - Kernel/USB/Disks": {
        "grep": r"(kernel|USB|IOUSB|USBF|IOMedia|fsck|SMART|I/O error|disk\d|eject|mount)",
        "exclude": r""
    },
    "macOS - Time Machine/Backup": {
        "grep": r"(backupd|Time Machine|tmutil|com\.apple\.TimeMachine|snapshot|APFS.*snapshot)",
        "exclude": r""
    },
    "macOS - App Store/Updates": {
        "grep": r"(softwareupdated|storeassetd|appstore|assetd|installd|package|mdmclient|ManagedClient)",
        "exclude": r""
    },

    # --- Windows focused sub-presets (more granular) ---
    "Windows - Network/Connection": {
        "grep": r"(DNS Client Events|Tcpip|WLAN|NetBT|NetworkProfile|Dhcp|NlaSvc|NameResolution|timeout|disconnected|unreachable)",
        "exclude": r""
    },
    "Windows - Battery/Power": {
        "grep": r"(Kernel-Power|Power-Troubleshooter|ACPI|battery|power|thermal|sleep|resume|hibernate)",
        "exclude": r""
    },
    "Windows - Windows Update": {
        "grep": r"(WindowsUpdateClient|WUA|Servicing|CBS|Component-Based Servicing|Windows Installer|MUClient|SIH)",
        "exclude": r""
    },
    "Windows - Disk/Storage": {
        "grep": r"(disk|Ntfs|volsnap|defrag|storahci|stornvme|bad block|SMART|I/O error)",
        "exclude": r""
    },
    "Windows - Login/Profile/Auth": {
        "grep": r"(User Profile|User Profile Service|Winlogon|GroupPolicy|LSA|Schannel|Kerberos|NTLM|Logon)",
        "exclude": r""
    }
}

def export_csv(base_path, ip_counts, msg_counts, sev_counts, proc_counts, redact=False):
    ip_path = f"{base_path}_ips.csv"
    msg_path = f"{base_path}_messages.csv"
    sev_path = f"{base_path}_severity.csv"
    with open(ip_path, "w") as f:
        f.write("ip,count\n")
        for ip,count in ip_counts.most_common():
            f.write(f"{ip},{count}\n")
    with open(msg_path, "w") as f:
        f.write("count,message\n")
        for msg,count in msg_counts.most_common():
            if redact:
                msg = redact_text(msg)
            safe = msg.replace('"','\"\"')
            f.write(f'{count},"{safe}"\n')
    with open(sev_path, "w") as f:
        f.write("severity,count\n")
        for k,v in sev_counts.items():
            f.write(f"{k},{v}\n")
    proc_path = f"{base_path}_procs.csv"
    with open(proc_path, "w") as f:
        f.write("process,count\n")
        for p,c in proc_counts.most_common():
            f.write(f"{p},{c}\n")
    return ip_path, msg_path, sev_path, proc_path

def export_md(path, ip_counts, msg_counts, sev_counts, proc_counts, top_ips, top_msgs, top_procs, redact=False):
    with open(path, "w") as f:
        f.write("# System Log Analyzer Report\n\n")
        f.write("## Severity Summary\n\n| Severity | Count |\n|---|---:|\n")
        for k in ['fatal','critical','error','warning','fail','notice']:
            if sev_counts[k]:
                f.write(f"| {k.title()} | {sev_counts[k]} |\n")
        f.write("\n")
        if ip_counts:
            f.write(f"## Top {top_ips} IPs\n\n| IP | Count |\n|---|---:|\n")
            for ip,count in ip_counts.most_common(top_ips):
                f.write(f"| {ip} | {count} |\n")
            f.write("\n")
        if msg_counts:
            f.write(f"## Top {top_msgs} Messages\n\n| Count | Message |\n|---:|---|\n")
            for msg,count in msg_counts.most_common(top_msgs):
                if redact:
                    msg = redact_text(msg)
                safe = msg.replace("|","\\|")
                f.write(f"| {count} | {safe} |\n")
        if proc_counts:
            f.write(f"\n## Top {top_procs} Processes\n\n| Process | Count |\n|---|---:|\n")
            for p,c in proc_counts.most_common(top_procs):
                f.write(f"| {p} | {c} |\n")

def load_lines(path):
    if path == "-" or path == "/dev/stdin":
        return sys.stdin.read().splitlines()
    if path.endswith(".gz"):
        with gzip.open(path, "rt", errors="ignore") as f:
            return f.readlines()
    with open(path, "r", errors="ignore") as f:
        return f.readlines()

def compute_stats(lines, grep=None, exclude=None, since=None, until=None):
    pat = re.compile(grep, re.IGNORECASE) if grep else None
    xpat = re.compile(exclude, re.IGNORECASE) if exclude else None
    since_dt = dt.datetime.fromisoformat(since.replace('T',' ')) if since else None
    until_dt = dt.datetime.fromisoformat(until.replace('T',' ')) if until else None

    sev_counts = Counter()
    msg_counts = Counter()
    ip_counts  = Counter()
    proc_counts = Counter()

    for line in lines:
        if xpat and xpat.search(line): 
            continue
        if pat and not pat.search(line):
            continue
        if since_dt or until_dt:
            ts = parse_line_ts(line)
            if ts:
                if since_dt and ts < since_dt: 
                    continue
                if until_dt and ts > until_dt:
                    continue

        m = SEVERITY_RE.search(line)
        if m:
            sev = normalize_severity(m.group(1) or m.group(2))
            sev_counts[sev] += 1
            msg_counts[strip_prefix(line)] += 1

        for ip in IP_RE.findall(line):
            ip_counts[ip] += 1

        p = extract_proc(line)
        if p: 
            proc_counts[p] += 1

    return sev_counts, ip_counts, msg_counts, proc_counts

def streamlit_ui():
    try:
        import streamlit as st
        import pandas as pd
    except Exception as e:
        print("Streamlit UI requested, but required packages are missing.")
        print("Install with: pip install streamlit pandas")
        return

    st.set_page_config(page_title="System Log Analyzer", layout="wide")
    st.title("System Log Management (Windows + Mac)")

    with st.sidebar:
        preset = st.selectbox("Preset (optional)", ["None"] + list(PRESETS.keys()), index=0)
        apply_preset = st.button("Apply preset")
        file_source = st.radio("Source", ["Upload file", "Path on disk"], index=0)
        # Choose source and collect input
        if file_source == "Upload file":
            uploaded = st.file_uploader("Log file (.log / .txt / .gz)", type=["log","txt","gz"])
            path = ""
        else:
            uploaded = None
            path = st.text_input("Path (or '-' for stdin)", value="")

        # Preset apply
        if apply_preset and preset != "None":
            st.session_state["grep"] = PRESETS[preset]["grep"]
            st.session_state["exclude"] = PRESETS[preset]["exclude"]

        # --- Quick time ranges (set before widgets are created) ---
        def _set_since(minutes):
            st.session_state["since"] = (dt.datetime.now() - dt.timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")
            st.rerun()

        colq1, colq2, colq3 = st.columns(3)
        colq1.button("Last 15m", on_click=_set_since, args=(15,))
        colq2.button("Last 1h",  on_click=_set_since, args=(60,))
        colq3.button("Last 24h", on_click=_set_since, args=(24*60,))

        # Now create the widgets that read from session_state
        grep = st.text_input("Include (regex)", key="grep", value=st.session_state.get("grep",""))
        exclude = st.text_input("Exclude (regex)", key="exclude", value=st.session_state.get("exclude",""))
        since = st.text_input("Since (YYYY-MM-DD HH:MM:SS)", key="since", value=st.session_state.get("since",""))
        until = st.text_input("Until (YYYY-MM-DD HH:MM:SS)", key="until", value=st.session_state.get("until",""))
        # Redaction toggle
        redact_ui = st.checkbox("Redact emails/hostnames in messages (exports & tables)", value=False)
        top_ips = st.number_input("Top IPs", min_value=0, max_value=100, value=10, step=1)
        top_msgs = st.number_input("Top Messages", min_value=0, max_value=200, value=20, step=1)
        top_procs = st.number_input("Top Processes", min_value=0, max_value=100, value=10, step=1)
        run = st.button("Analyze")

    if not run:
        st.info("Select a log source and click **Analyze**.")
        if st.session_state.get("grep") or st.session_state.get("exclude"):
            st.caption("Preset applied — you can tweak the fields on the left before clicking **Analyze**.")
        return

    # Load lines
    if uploaded is not None:
        if uploaded.name.endswith(".gz"):
            import io, gzip as gz
            with gz.open(io.BytesIO(uploaded.read()), "rt", errors="ignore") as f:
                lines = f.readlines()
        else:
            lines = uploaded.read().decode(errors="ignore").splitlines()
    elif path:
        lines = load_lines(path)
    else:
        st.warning("Please upload a file or provide a path.")
        return

    total = len(lines)
    sev_counts, ip_counts, msg_counts, proc_counts = compute_stats(
        lines, grep=grep or None, exclude=exclude or None, since=since or None, until=until or None
    )

    colA,colB,colC,colD = st.columns(4)
    colA.metric("Lines analyzed", f"{total:,}")
    colB.metric("Errors", sev_counts.get('error',0))
    colC.metric("Warnings", sev_counts.get('warning',0))
    colD.metric("Critical/Fatal", sev_counts.get('critical',0)+sev_counts.get('fatal',0))

    # Severity bar chart
    sev_rows = [{"severity": k.title(), "count": v} for k, v in sev_counts.items() if v > 0]
    sev_df = pd.DataFrame(sev_rows, columns=["severity", "count"])
    if not sev_df.empty:
        sev_df = sev_df.sort_values("count", ascending=False)
        st.subheader("Severity Summary")
        st.bar_chart(sev_df.set_index("severity"))

        # Severity Pie Chart (Final Fix – adaptive labels with leader lines)
        if not sev_df.empty:
            import matplotlib.pyplot as plt
            from matplotlib.animation import FuncAnimation
            import numpy as np

            custom_colors = ["#84949f", '#ff7f0e', "#e44100"]  # blue, orange, green

            plt.style.use('dark_background')
            fig, ax = plt.subplots(figsize=(5, 5), facecolor='none')
            ax.axis('equal')

            total = sev_df['count'].sum()
            fractions = sev_df['count'] / total

            # Helper function for label positioning
            def autopct_generator(limit):
                """Hide labels for very small slices."""
                def inner_autopct(pct):
                    return f'{pct:.1f}%' if pct > limit else ''
                return inner_autopct

            def animate(i):
                ax.clear()
                ax.axis('equal')
                wedges, texts, autotexts = ax.pie(
                    sev_df['count'],
                    labels=sev_df['severity'],
                    autopct=autopct_generator(1),  # Hide below 1%
                    startangle=90,
                    colors=custom_colors[:len(sev_df)],
                    pctdistance=0.75,
                    labeldistance=1.25,  # move labels outward
                    wedgeprops={'linewidth': 1, 'edgecolor': 'black'},
                    textprops={'color': 'white', 'fontsize': 12},
                )

                # Add leader lines for outside labels
                for w in wedges:
                    w.set_linewidth(0.5)
                    w.set_edgecolor('black')

                for text in texts + autotexts:
                    text.set_color('white')
                    text.set_fontsize(12)

            # Animate and display
            anim = FuncAnimation(fig, animate, frames=np.arange(1, 11), interval=80, repeat=False)
            animate(10)

            st.pyplot(fig, use_container_width=True)
            
    else:
        st.subheader("Severity Summary")
        st.caption("No matching severities for the current preset/time filters.")

    # Top IPs
    if top_ips and ip_counts:
        st.subheader(f"Top {top_ips} IPs")
        ip_df = pd.DataFrame(ip_counts.most_common(top_ips), columns=["ip","count"])
        st.dataframe(ip_df, use_container_width=True)

    # Top Messages
    if top_msgs and msg_counts:
        st.subheader(f"Top {top_msgs} Messages")
        raw_msgs = msg_counts.most_common(top_msgs)
        if redact_ui:
            raw_msgs = [(redact_text(m), c) for (m,c) in raw_msgs]
        msg_df = pd.DataFrame(raw_msgs, columns=["message","count"])
        st.dataframe(msg_df[["count","message"]], use_container_width=True)

    # Top Processes
    if top_procs and proc_counts:
        st.subheader(f"Top {top_procs} Processes")
        proc_df = pd.DataFrame(proc_counts.most_common(top_procs), columns=["process","count"])
        st.dataframe(proc_df, use_container_width=True)

    # Download buttons
    with st.expander("Downloads"):
        if ip_counts:
            st.download_button("Download IPs CSV", ip_df.to_csv(index=False).encode(), file_name="ips.csv", mime="text/csv")
        if msg_counts:
            st.download_button("Download Messages CSV", msg_df.to_csv(index=False).encode(), file_name="messages.csv", mime="text/csv")
        if sev_counts:
            st.download_button("Download Severity CSV", sev_df.rename(columns={"severity":"sev"}).to_csv(index=False).encode(), file_name="severity.csv", mime="text/csv")
        if proc_counts:
            st.download_button("Download Processes CSV", proc_df.to_csv(index=False).encode(), file_name="processes.csv", mime="text/csv")

def analyze_log(file_path, top_ips=5, top_msgs=5, grep=None, exclude=None, since=None, until=None, since_rel=None, until_rel=None, top_procs=5, export_csv_base=None, export_md_path=None, redact=False):
    lines = load_lines(file_path)

    pat = re.compile(grep, re.IGNORECASE) if grep else None
    xpat = re.compile(exclude, re.IGNORECASE) if exclude else None
    # Absolute times
    since_dt = dt.datetime.fromisoformat(since.replace('T',' ')) if since else None
    until_dt = dt.datetime.fromisoformat(until.replace('T',' ')) if until else None
    # Relative overrides (e.g., 15m, 2h, 1d)
    rsince = parse_relative(since_rel) if since_rel else None
    runtil = parse_relative(until_rel) if until_rel else None
    since_dt = rsince or since_dt
    until_dt = runtil or until_dt

    total = len(lines)
    sev_counts = Counter()
    msg_counts = Counter()
    ip_counts  = Counter()
    proc_counts = Counter()

    for line in lines:
        if xpat and xpat.search(line):
            continue
        if pat and not pat.search(line):
            continue
        if since_dt or until_dt:
            ts = parse_line_ts(line)
            if ts:
                if since_dt and ts < since_dt:
                    continue
                if until_dt and ts > until_dt:
                    continue

        m = SEVERITY_RE.search(line)
        if m:
            sev = normalize_severity(m.group(1) or m.group(2))
            sev_counts[sev] += 1
            msg_counts[strip_prefix(line)] += 1

        for ip in IP_RE.findall(line):
            ip_counts[ip] += 1

        p = extract_proc(line)
        if p: 
            proc_counts[p] += 1

    print(f"Lines analyzed: {total}")

    print("Error Summary:")
    any_hit = False
    for key in ['fatal','critical','error','warning','fail','notice']:
        if sev_counts[key]:
            any_hit = True
            print(f"  {key.title()}: {sev_counts[key]}")
    if not any_hit:
        print("  (No standard severity keywords found. Try --grep 'keyword')")

    if top_ips and ip_counts:
        print(f"\nTop {top_ips} IPs:")
        for ip, count in ip_counts.most_common(top_ips):
            print(f"  {ip}: {count}")

    if top_msgs and msg_counts:
        print(f"\nTop {top_msgs} Messages:")
        for msg, count in msg_counts.most_common(top_msgs):
            print(f"  [{count}] {msg[:180]}")

    if top_procs and proc_counts:
        print(f"\nTop {top_procs} Processes:")
        for p,c in proc_counts.most_common(top_procs):
            print(f"  {p}: {c}")

    if export_csv_base:
        paths = export_csv(export_csv_base, ip_counts, msg_counts, sev_counts, proc_counts, redact=redact)
        print(f"\nCSV exported: {', '.join(paths)}")
    if export_md_path:
        export_md(export_md_path, ip_counts, msg_counts, sev_counts, proc_counts, top_ips, top_msgs, top_procs, redact=redact)
        print(f"Markdown report: {export_md_path}")

def cli():
    p = argparse.ArgumentParser(description="System Log Analyzer")
    p.add_argument("--file", required=True, help="Path to log file (or '-' for stdin)")
    p.add_argument("--top",  type=int, default=5, help="Top N IPs to show")
    p.add_argument("--msgs", type=int, default=5, help="Top N repeated messages to show")
    p.add_argument("--grep", help="Filter log lines by a regex (case-insensitive)")
    p.add_argument("--export-csv", help="Base path for CSV export (creates *_ips.csv, *_messages.csv, *_severity.csv)")
    p.add_argument("--export-md",  help="Path to Markdown report file")
    p.add_argument("--exclude", help="Regex to exclude lines (applied after --grep)")
    p.add_argument("--since", help="Only include lines with timestamp >= this ISO time (e.g., 2025-10-06 09:00:00)")
    p.add_argument("--until", help="Only include lines with timestamp <= this ISO time (e.g., 2025-10-06 12:00:00)")
    p.add_argument("--top-procs", type=int, default=5, help="Top N processes to show")
    p.add_argument("--since-rel", help="Relative since (e.g., 15m, 2h, 1d)")
    p.add_argument("--until-rel", help="Relative until (e.g., 15m, 2h, 1d)")
    p.add_argument("--redact", action="store_true", help="Redact emails/hostnames in message outputs")
    args = p.parse_args()
    analyze_log(args.file, top_ips=args.top, top_msgs=args.msgs, grep=args.grep,
                exclude=args.exclude, since=args.since, until=args.until,
                since_rel=args.since_rel, until_rel=args.until_rel,
                top_procs=args.top_procs, export_csv_base=args.export_csv,
                export_md_path=args.export_md, redact=args.redact)

if __name__ == "__main__":
    # If launched by `streamlit run analyzer.py`, skip CLI and render UI.
    if 'streamlit' in sys.modules:
        streamlit_ui()
    else:
        cli()