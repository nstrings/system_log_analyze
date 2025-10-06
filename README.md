# System Log Analyzer (macOS + Windows)

Interactive **Streamlit** UI + CLI tool to analyze system/application logs.

- macOS: analyze `log show` exports
- Windows: analyze `Get-WinEvent` exports
- Presets for Networking, Security, Windows (DNS/SCM/Schannel/GPO)
- Exports CSV and Markdown reports

## Quickstart (UI)
```bash
pip install -r requirements.txt
streamlit run analyzer.py
```

## Quickstart (CLI)
```bash
# macOS
log show --style syslog --last 30m > sample.log
python3 analyzer.py --file sample.log --msgs 20 --top 20 --top-procs 10 \
  --export-md report.md --export-csv report
```

## Windows export (PowerShell)
```powershell
Get-WinEvent -LogName System -MaxEvents 5000 | ForEach-Object {
  "$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) $($_.LevelDisplayName) $($_.ProviderName) $($_.Message -replace '\r?\n',' ')" 
} | Out-File -Encoding utf8 C:\Temp\sample_windows.log
```

## Notes
- Do not upload real logs; sanitize if needed.
- Works with `.log`, `.txt`, and `.gz` files.
