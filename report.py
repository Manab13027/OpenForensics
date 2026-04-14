"""
HTML Report Generator
Produces a self-contained HTML report styled like a forensic terminal.
"""

from datetime import datetime
from pathlib import Path


def _esc(text):
    """HTML-escape a string."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _rows(data, *keys):
    html = ""
    for r in data:
        html += "<tr>" + "".join(f"<td>{_esc(r.get(k,''))}</td>" for k in keys) + "</tr>\n"
    return html or "<tr><td colspan='99' style='color:#888'>No data found.</td></tr>"


CSS = """
body{font-family:'Courier New',monospace;background:#0d0d0d;color:#00ff41;
     margin:0;padding:24px;font-size:13px}
h1{font-size:1.6em;letter-spacing:4px;color:#00ff41;border-bottom:2px solid #00ff41;
   padding-bottom:8px;margin-bottom:4px}
h2{font-size:1.1em;color:#00cc33;border-bottom:1px solid #004400;padding-bottom:4px;
   margin-top:40px;letter-spacing:2px}
.meta{color:#558855;margin-bottom:24px;font-size:0.85em}
.badge{background:#00ff41;color:#000;padding:1px 7px;border-radius:2px;
       font-size:0.8em;margin-left:8px;font-weight:bold}
table{width:100%;border-collapse:collapse;margin-top:6px}
th{background:#001800;color:#00ff41;padding:7px 10px;text-align:left;
   border:1px solid #003300;font-size:0.8em;letter-spacing:1px}
td{padding:5px 10px;border:1px solid #001a00;font-size:0.8em;
   word-break:break-all;max-width:380px;overflow:hidden;
   text-overflow:ellipsis;white-space:nowrap}
tr:nth-child(even){background:#060f06}
tr:hover{background:#0a1f0a}
.removed{color:#ff5555}
.installed{color:#00ff41}
.footer{margin-top:48px;color:#334433;font-size:0.75em;
        border-top:1px solid #003300;padding-top:12px}
a{color:#00cc33}
"""


class ReportGenerator:

    def __init__(self, browser, apps, files, scan_target="Local Machine", deleted=None):
        self.browser = browser
        self.apps = apps
        self.files = files
        self.deleted = deleted or []
        self.scan_target = scan_target
        self.ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate(self, output_path: str) -> str:
        # Removed apps get a different class
        app_rows = ""
        for r in self.apps:
            status_cls = "removed" if r.get("status") == "Removed" else "installed"
            app_rows += (
                f"<tr>"
                f"<td>{_esc(r.get('name',''))}</td>"
                f"<td>{_esc(r.get('version',''))}</td>"
                f"<td>{_esc(r.get('publisher',''))}</td>"
                f"<td>{_esc(r.get('install_date',''))}</td>"
                f"<td class='{status_cls}'>{_esc(r.get('status',''))}</td>"
                f"<td>{_esc(r.get('source',''))}</td>"
                f"</tr>\n"
            )
        if not app_rows:
            app_rows = "<tr><td colspan='6' style='color:#888'>No data found.</td></tr>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenForensics Report — {_esc(self.ts)}</title>
<style>{CSS}</style>
</head>
<body>

<h1>&#x1F50D; OPENFORENSICS REPORT</h1>
<div class="meta">
  Generated&nbsp;&nbsp;: {_esc(self.ts)}<br>
  Scan Target: {_esc(self.scan_target)}<br>
  Tool&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: OpenForensics Demo v1.0 (Educational Use)<br>
</div>

<!-- ==================== BROWSER HISTORY ==================== -->
<h2>BROWSER HISTORY <span class="badge">{len(self.browser)}</span></h2>
<table>
<tr><th>Browser</th><th>Profile</th><th>Date / Time</th>
    <th>URL</th><th>Title</th><th>Visits</th></tr>
{_rows(self.browser,'browser','profile','last_visit','url','title','visit_count')}
</table>

<!-- ==================== APPLICATION INVENTORY ==================== -->
<h2>APPLICATION INVENTORY <span class="badge">{len(self.apps)}</span></h2>
<table>
<tr><th>Name</th><th>Version</th><th>Publisher</th>
    <th>Install Date</th><th>Status</th><th>Source</th></tr>
{app_rows}
</table>

<!-- ==================== DELETED APPS ==================== -->
<h2 style="color:#ff5555">DELETED / UNINSTALLED APPS <span class="badge" style="background:#ff5555">{len(self.deleted)}</span></h2>
<table>
<tr><th>Name</th><th>Version</th><th>Removed Date</th><th>Install Date</th>
    <th>Evidence / Reason</th><th>Source</th><th>Platform</th></tr>
{_rows(self.deleted,'name','version','removed_date','install_date','reason','source','platform')}
</table>

<!-- ==================== FILE ARTIFACTS ==================== -->
<h2>FILE ARTIFACTS <span class="badge">{len(self.files)}</span></h2>
<table>
<tr><th>Name</th><th>Type</th><th>Accessed</th><th>Path / URL</th><th>Source</th></tr>
{_rows(self.files,'name','type','accessed','path','source')}
</table>

<div class="footer">
  This report was generated for <strong>educational / forensic training purposes</strong> only.<br>
  Always obtain proper legal authorisation before conducting forensic analysis on systems
  you do not own or have written permission to examine.<br><br>
  OpenForensics Demo &mdash; open-source, no warranty.
</div>
</body>
</html>"""

        Path(output_path).write_text(html, encoding="utf-8")
        return output_path
