
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sensitive String Extractor (GUI)
--------------------------------
- Select a folder containing built HTML/CSS/JS files.
- Extracts string literals and text (JS, HTML, CSS).
- Flags potential sensitive information using common patterns (API keys, tokens, JWTs, emails, URLs with secrets, etc.).
- Displays results in a sortable table.
- Export results to CSV.
"""

import os
import re
import csv
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from html.parser import HTMLParser

APP_TITLE = "Sensitive String Extractor (HTML/CSS/JS)"
SUPPORTED_EXTS = {".html", ".htm", ".css", ".js", ".mjs", ".cjs"}

# -------- Sensitive pattern definitions --------
SENSITIVE_PATTERNS = [
    # Cloud/API keys
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key (heuristic)", re.compile(r"(?i)aws(.{0,30})?(secret|access).{0,30}?['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Firebase URL", re.compile(r"[a-z0-9-]+\.firebaseio\.com")),
    ("Stripe Live Secret", re.compile(r"sk_live_[0-9a-zA-Z]{10,}")),
    ("Stripe Publishable", re.compile(r"pk_live_[0-9a-zA-Z]{10,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Twilio Account SID", re.compile(r"AC[0-9a-fA-F]{32}")),
    ("Google OAuth Client ID", re.compile(r"\d+-[a-z0-9\-]+\.apps\.googleusercontent\.com")),
    ("Mapbox Token", re.compile(r"pk\.[0-9a-zA-Z]{60,}")),
    # Secrets in URLs
    ("URL with secret-like param", re.compile(r"(?i)(?:key|token|secret|password|passwd|pwd)=[^&\s]{6,}")),
    # Credentials and tokens
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    # PII indicators (lower severity)
    ("Email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("IPv4 Address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# Severity mapping
SEVERITY = {
    "Private Key Block": "High",
    "AWS Access Key ID": "High",
    "AWS Secret Access Key (heuristic)": "High",
    "Google API Key": "High",
    "Stripe Live Secret": "High",
    "Slack Token": "High",
    "Twilio Account SID": "High",
    "Mapbox Token": "High",
    "JWT": "Medium",
    "URL with secret-like param": "Medium",
    "Firebase URL": "Medium",
    "Google OAuth Client ID": "Medium",
    "Stripe Publishable": "Low",
    "Email": "Low",
    "IPv4 Address": "Low",
}

# -------- Extractors --------

JS_STRING_RE = re.compile(
    r"""
    ("(?:\\.|[^"\\])*")        # double-quoted
    |('(?:\\.|[^'\\])*')       # single-quoted
    |(`(?:\\.|[^`\\])*`)       # backtick (template literal, no interpolation handling)
    """,
    re.VERBOSE | re.DOTALL,
)

CSS_STRING_RE = re.compile(
    r"""
    # url(...) or content:"..." / '...'
    url\(\s*([^)]+?)\s*\)
    |content\s*:\s*(?P<q>['"])(?P<content>(?:\\.|[^\\])*)?(?P=q)
    |("(?:(?:\\.|[^"\\])*)")|('(?:(?:\\.|[^'\\])*)')
    """,
    re.VERBOSE | re.DOTALL | re.IGNORECASE,
)

class SimpleHTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.texts = []    # (data, line)
        self.attrs = []    # (value, line, attrname, tag)

    def handle_data(self, data):
        clean = data.strip()
        if clean:
            # getpos gives (lineno, offset)
            lineno, _ = self.getpos()
            self.texts.append((clean, lineno))

    def handle_starttag(self, tag, attrs):
        lineno, _ = self.getpos()
        for k, v in attrs:
            if v and isinstance(v, str):
                self.attrs.append((v, lineno, k, tag))

# -------- Core scanning --------

def detect_sensitivity(s: str):
    reasons = []
    for name, pattern in SENSITIVE_PATTERNS:
        if pattern.search(s):
            reasons.append(name)
    if not reasons:
        return ("None", [])
    # pick worst severity
    worst = "Low"
    for r in reasons:
        sev = SEVERITY.get(r, "Low")
        if sev == "High":
            worst = "High"; break
        if sev == "Medium" and worst == "Low":
            worst = "Medium"
    return (worst, reasons)

def normalize_string(s: str):
    # Trim quotes/backticks if present
    if (len(s) >= 2) and ((s[0] == s[-1]) and s[0] in ("'", '"', '`')):
        return s[1:-1]
    return s

def scan_js(filepath):
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        # We also want line numbers: iterate through matches and compute line by start index
        for m in JS_STRING_RE.finditer(text):
            s = m.group(0)
            # Skip template literals that contain interpolation (${...}) to reduce noise
            if s.startswith('`') and "${" in s:
                continue
            value = normalize_string(s)
            if not value.strip():
                continue
            # line number
            line = text.count("\n", 0, m.start()) + 1
            sev, reasons = detect_sensitivity(value)
            results.append((filepath, line, value, "JS String", sev, "; ".join(reasons)))
    except Exception as e:
        results.append((filepath, 0, f"[ERROR reading file: {e}]", "Error", "None", ""))
    return results

def scan_css(filepath):
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        for m in CSS_STRING_RE.finditer(text):
            s = m.group(0)
            # Extract the inner for url() or content
            url_group = m.group(1)
            if url_group:
                candidate = url_group.strip().strip('\'"')
                kind = "CSS url()"
                start_index = m.start(1)
            elif m.group("content") is not None:
                candidate = m.group("content")
                kind = "CSS content"
                start_index = m.start("content")
            else:
                candidate = normalize_string(s)
                kind = "CSS String"
                start_index = m.start()
            if not candidate.strip():
                continue
            line = text.count("\n", 0, start_index) + 1
            sev, reasons = detect_sensitivity(candidate)
            results.append((filepath, line, candidate, kind, sev, "; ".join(reasons)))
    except Exception as e:
        results.append((filepath, 0, f"[ERROR reading file: {e}]", "Error", "None", ""))
    return results

def scan_html(filepath):
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        parser = SimpleHTMLTextExtractor()
        parser.feed(text)

        for data, line in parser.texts:
            sev, reasons = detect_sensitivity(data)
            results.append((filepath, line, data, "HTML Text", sev, "; ".join(reasons)))

        for value, line, attr, tag in parser.attrs:
            # Only care about common attrs likely to include strings/URLs
            if attr.lower() in {"href", "src", "content", "action", "value", "data", "data-src", "data-href"} or any(k in attr.lower() for k in ["token", "key", "secret"]):
                sev, reasons = detect_sensitivity(value)
                results.append((filepath, line, value, f"HTML attr {tag}.{attr}", sev, "; ".join(reasons)))
    except Exception as e:
        results.append((filepath, 0, f"[ERROR reading file: {e}]", "Error", "None", ""))
    return results

def scan_path(root_path):
    rows = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SUPPORTED_EXTS:
                fp = os.path.join(dirpath, fn)
                if ext in {".js", ".mjs", ".cjs"}:
                    rows.extend(scan_js(fp))
                elif ext in {".css"}:
                    rows.extend(scan_css(fp))
                else:
                    rows.extend(scan_html(fp))
    return rows

# -------- GUI --------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1100x640")
        self.minsize(900, 560)

        self.path_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.filter_var = tk.StringVar(value="All")

        # Top controls
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="Folder:").pack(side="left")
        self.path_entry = ttk.Entry(top, textvariable=self.path_var, width=70)
        self.path_entry.pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(top, text="Browse…", command=self.browse).pack(side="left", padx=4)
        ttk.Button(top, text="Scan", command=self.scan).pack(side="left", padx=4)

        # Filter by severity
        ttk.Label(top, text="Severity:").pack(side="left", padx=(16, 4))
        self.filter_combo = ttk.Combobox(top, values=["All", "High", "Medium", "Low", "None"], textvariable=self.filter_var, width=8, state="readonly")
        self.filter_combo.current(0)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())
        self.filter_combo.pack(side="left")

        # Treeview
        columns = ("file", "line", "kind", "severity", "reasons", "string")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        self.tree.heading("file", text="File")
        self.tree.heading("line", text="Line")
        self.tree.heading("kind", text="Type")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("reasons", text="Detected As")
        self.tree.heading("string", text="Extracted String")

        self.tree.column("file", width=280, anchor="w")
        self.tree.column("line", width=60, anchor="e")
        self.tree.column("kind", width=120, anchor="w")
        self.tree.column("severity", width=80, anchor="center")
        self.tree.column("reasons", width=200, anchor="w")
        self.tree.column("string", width=600, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Scrollbars
        yscroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        yscroll.place(in_=self.tree, relx=1.0, rely=0, relheight=1.0, x=-2)
        self.tree.configure(yscrollcommand=yscroll.set)

        # Bottom buttons
        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Copy Selected", command=self.copy_selected).pack(side="left")
        ttk.Button(bottom, text="Export CSV", command=self.export_csv).pack(side="left", padx=6)
        ttk.Label(bottom, textvariable=self.status_var).pack(side="right")

        # Data store
        self.all_rows = []   # list of tuples: (file, line, string, kind, severity, reasons)

        # Style tweaks
        style = ttk.Style()
        try:
            style.theme_use("default")
        except:
            pass
        style.configure("Treeview", rowheight=22)
        style.map("Treeview")

        # Tag styles per severity
        self.tree.tag_configure("High", background="#ffe5e5")
        self.tree.tag_configure("Medium", background="#fff5e6")
        self.tree.tag_configure("Low", background="#eef7ff")
        self.tree.tag_configure("None", background="#f6f6f6")

        # Bind double-click to copy
        self.tree.bind("<Double-1>", lambda e: self.copy_selected())

    def browse(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            self.path_var.set(path)

    def scan(self):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning(APP_TITLE, "Please select a folder first.")
            return
        if not os.path.isdir(path):
            messagebox.showerror(APP_TITLE, "Invalid folder path.")
            return
        self.status_var.set("Scanning...")
        self.update_idletasks()
        try:
            rows = scan_path(path)
            self.all_rows = rows
            self.refresh_tree()
            self.status_var.set(f"Found {len(rows)} strings in {path}")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Scan failed: {e}")
            self.status_var.set("Error")

    def refresh_tree(self):
        # Clear
        for item in self.tree.get_children():
            self.tree.delete(item)
        # Insert current filtered view
        sev_filter = self.filter_var.get()
        for (file, line, string, kind, severity, reasons) in self.all_rows:
            if sev_filter != "All" and severity != sev_filter:
                continue
            # shorten very long string in table display
            display_str = string if len(string) <= 200 else string[:200] + "…"
            self.tree.insert("", "end", values=(file, line, kind, severity, reasons, display_str), tags=(severity,))

    def apply_filter(self):
        self.refresh_tree()

    def copy_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        # Copy extracted strings of selected rows to clipboard
        strings = []
        for item in selected:
            vals = self.tree.item(item, "values")
            # values: file, line, kind, severity, reasons, string
            s = vals[5]
            strings.append(s)
        txt = "\n".join(strings)
        self.clipboard_clear()
        self.clipboard_append(txt)
        self.status_var.set(f"Copied {len(strings)} string(s) to clipboard")

    def export_csv(self):
        if not self.all_rows:
            messagebox.showwarning(APP_TITLE, "No data to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export results to CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")]
        )
        if not path:
            return
        sev_filter = self.filter_var.get()
        to_write = [("file","line","type","severity","detected_as","string")]
        for (file, line, string, kind, severity, reasons) in self.all_rows:
            if sev_filter != "All" and severity != sev_filter:
                continue
            to_write.append((file, line, kind, severity, reasons, string))
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerows(to_write)
            messagebox.showinfo(APP_TITLE, f"Exported {len(to_write)-1} rows to {path}")
        except Exception as e:
            messagebox.showerror(APP_TITLE, f"Export failed: {e}")


def main():
    root = App()
    root.mainloop()

if __name__ == "__main__":
    main()
