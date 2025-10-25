import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import tkinter.font as tkfont
import zipfile
import os
import plistlib
import tempfile
import shutil
import hashlib
import stat
import datetime
import json
import re
from io import BytesIO

SUSPICIOUS_ENTITLEMENT_SUBSTRINGS = (
    "com.apple.private",
    "com.apple.developer.kernel-extension",
    "com.apple.developer.device-lockdown",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.networking.vpn",
    "com.apple.security.cs",
    "com.apple.developer.in-app-payments",
    "com.apple.developer.facialrecognition",
    "com.apple.developer.healthkit",
    "com.apple.developer.homekit",
    "com.apple.developer.siri",
    "com.apple.developer.device-management",
    "com.apple.developer.kernel",
    "com.apple.developer.pass-type-identifiers",
    "com.apple.developer.contacts.notes",
    "com.apple.developer.location.always",
    "com.apple.developer.family-controls",
    "com.apple.developer.payment-pass-provisioning",
    "com.apple.developer.push-to-talk",
    "com.apple.security.network.server",
    "com.apple.security.network.client",
)

HIGH_RISK_KEYS = (
    "get-task-allow",
    "keychain-access-groups",
    "com.apple.developer.kernel-extension",
    "com.apple.private",
    "com.apple.developer.device-lockdown",
    "com.apple.security.app-sandbox",
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.cs.debugger",
)

SUSPICIOUS_STRINGS = (
    b"Cydia", b"Sileo", b"Zebra", b"unc0ver", b"Taurine", b"checkra1n",
    b"Frida", b"cycript", b"Cycript", b"Substrate", b"substrate",
    b"MSHookFunction", b"_performTask", b"task_for_pid", b"performSelector"
)

PRIVATE_FRAMEWORKS = (
    "AppPrediction", "CoreDuet", "CoreFollowUp", "CoreHandwriting",
    "CoreRecognition", "CoreRoutine", "CoreSuggestions", "CoreUtils",
    "FTServices", "IMCore", "MobileCoreServices", "TelephonyUtilities",
    "SpringBoardServices", "UserManagement",
)

EXECUTABLE_EXTS = (".dylib", ".so", ".framework", "")
SCRIPT_EXTS = (".sh", ".pl", ".py", ".rb", ".js", ".command")

URL_REGEX = re.compile(rb'https?://[^\s"\'<>]+', re.IGNORECASE)

def read_plist_bytes(data):
    try:
        return plistlib.loads(data)
    except Exception:
        try:
            s_idx = data.find(b"<?xml")
            e_idx = data.find(b"</plist>")
            if s_idx != -1 and e_idx != -1:
                return plistlib.loads(data[s_idx : e_idx + 8])
        except Exception:
            return None
    return None

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def zip_entry_unix_mode(zinfo):
    try:
        return (zinfo.external_attr >> 16) & 0xFFFF
    except Exception:
        return 0

def looks_macho(data):
    if len(data) < 4:
        return False
    magic = data[:4]
    return magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

class Analyzer:
    def __init__(self, ipa_path):
        self.ipa_path = ipa_path
        self.tmpdir = tempfile.mkdtemp()
        self.findings = []
        self.score = 0
        self.details = {
            "info": {},
            "entitlements": {},
            "files": [],
            "file_tree": {},
            "extracted_urls": [],
            "suspicious_strings": [],
            "private_frameworks": [],
        }

    def _add_finding(self, category, info, score_increase):
        self.findings.append((category, info))
        self.score += score_increase

    def _scan_file_content(self, data, filename):
        try:
            urls = URL_REGEX.findall(data)
            for url in urls:
                self.details["extracted_urls"].append(url.decode(errors="ignore"))

            for s_str in SUSPICIOUS_STRINGS:
                if s_str in data:
                    self.details["suspicious_strings"].append(s_str.decode(errors="ignore"))
        except Exception as e:
            print(f"Error scanning file {filename}: {e}")

    def run(self):
        try:
            with zipfile.ZipFile(self.ipa_path, "r") as z:
                z.extractall(self.tmpdir)
                payload = os.path.join(self.tmpdir, "Payload")
                app_path = None
                if os.path.exists(payload):
                    for it in os.listdir(payload):
                        if it.endswith(".app"):
                            app_path = os.path.join(payload, it)
                            break
                
                if not app_path:
                    self._add_finding("Error", "Payload/*.app not found", 10)
                    return
                
                self.details["app_path"] = app_path
                app_name = os.path.basename(app_path)
                app_prefix = os.path.join("Payload", app_name)

                info_plist_path = os.path.join(app_path, "Info.plist")
                if os.path.exists(info_plist_path):
                    try:
                        with open(info_plist_path, "rb") as f:
                            info = plistlib.load(f)
                        self.details["info"] = info
                        bid = info.get("CFBundleIdentifier", "unknown")
                        bn = info.get("CFBundleName", info.get("CFBundleDisplayName", "unknown"))
                        ver = info.get("CFBundleShortVersionString", info.get("CFBundleVersion", "unknown"))
                        self._add_finding("App", f"{bn} ({bid}) v{ver}", 0)

                        if info.get("UIFileSharingEnabled"):
                            self._add_finding("Sandbox", "UIFileSharingEnabled = true (file sharing)", 2)
                        
                        ats = info.get("NSAppTransportSecurity")
                        if ats and ats.get("NSAllowsArbitraryLoads"):
                            self._add_finding("Network", "NSAllowsArbitraryLoads = true (ATS disabled)", 2)
                        
                        if info.get("LSApplicationQueriesSchemes"):
                            self._add_finding("Info", f"URL schemes queried: {len(info.get('LSApplicationQueriesSchemes'))}", 1)

                        if info.get("UIBackgroundModes"):
                            modes = ", ".join(info.get("UIBackgroundModes", []))
                            self._add_finding("Privacy", f"Background Modes: {modes}", 2)

                        perms = [k for k in info.keys() if k.endswith("UsageDescription")]
                        for p in perms:
                            self._add_finding("Permission", f"{p}: {info.get(p)}", 0)
                    except Exception as e:
                        self._add_finding("Warning", f"Info.plist parse error: {e}", 2)
                else:
                    self._add_finding("Warning", "Info.plist not found", 3)

                ent = {}
                ent_xcent_path = os.path.join(app_path, "archived-expanded-entitlements.xcent")
                mobileprov_path = os.path.join(app_path, "embedded.mobileprovision")

                if os.path.exists(ent_xcent_path):
                    try:
                        with open(ent_xcent_path, "rb") as f:
                            ent = plistlib.load(f)
                        self.details["entitlements_source"] = "archived-expanded-entitlements.xcent"
                    except Exception:
                        ent = {}
                
                if not ent and os.path.exists(mobileprov_path):
                    try:
                        with open(mobileprov_path, "rb") as f:
                            raw = f.read()
                        prov = read_plist_bytes(raw)
                        if prov:
                            ent = prov.get("Entitlements", {})
                            self.details["entitlements_source"] = "embedded.mobileprovision"
                    except Exception:
                        ent = {}

                if ent:
                    self.details["entitlements"] = ent
                    for k, v in ent.items():
                        if k in HIGH_RISK_KEYS:
                            if k == "get-task-allow" and v:
                                self._add_finding("Entitlement", "get-task-allow = true (debuggable)", 5)
                            elif k == "com.apple.security.app-sandbox" and not v:
                                self._add_finding("Entitlement", "App Sandbox = false (disabled!)", 5)
                            elif k.startswith("com.apple.security.cs") and v:
                                self._add_finding("Entitlement", f"High Risk: {k} = {v}", 5)
                            else:
                                self._add_finding("Entitlement", f"High Risk: {k} present", 4)
                        
                        if any(sub in k for sub in SUSPICIOUS_ENTITLEMENT_SUBSTRINGS):
                            self._add_finding("Entitlement", f"Suspicious: {k} present", 3)
                        
                        if "keychain-access-groups" in k:
                            self._add_finding("Keychain", str(v), 0)
                            if isinstance(v, (list, tuple)) and any("*" in str(g) for g in v):
                                self._add_finding("Keychain", "Wildcard in keychain-access-groups", 3)
                        
                        if isinstance(v, str) and "*" in v and "application-identifier" not in k:
                            self._add_finding("Entitlement", f"Wildcard value in {k}: {v}", 2)
                        
                        if "application-identifier" in k and isinstance(v, str) and "*" in v:
                            self._add_finding("Provision", f"Wildcard App ID: {v}", 3)
                else:
                    self._add_finding("Entitlements", "No entitlements found", 2)

                exec_like = []
                su_like = []
                script_like = []
                macho_count = 0
                file_tree = {}

                for zinfo in z.infolist():
                    if not zinfo.filename.startswith(app_prefix) or zinfo.is_dir():
                        continue
                    
                    rel_path = os.path.relpath(zinfo.filename, app_prefix)
                    self.details["files"].append(rel_path)

                    parts = rel_path.split(os.sep)
                    node = file_tree
                    for part in parts[:-1]:
                        node = node.setdefault(part, {})
                    node[parts[-1]] = "file"

                    mode = zip_entry_unix_mode(zinfo)
                    if bool(mode & stat.S_IXUSR):
                        exec_like.append(rel_path)
                    if bool(mode & stat.S_ISUID):
                        su_like.append(rel_path)
                        self._add_finding("Suspicious File", f"SetUID bit set: {rel_path}", 5)
                    
                    lower = rel_path.lower()
                    if lower.endswith(SCRIPT_EXTS):
                        script_like.append(rel_path)
                    
                    if any(s in lower for s in ("su", "sudo", "dropbear", "sshd")):
                        su_like.append(rel_path)

                    try:
                        raw = z.read(zinfo.filename)
                    except Exception:
                        raw = b""
                    
                    if looks_macho(raw):
                        macho_count += 1
                        self._scan_file_content(raw, rel_path)
                    
                    if rel_path.endswith(".js"):
                        self._scan_file_content(raw, rel_path)

                self.details["file_tree"] = file_tree

                if exec_like:
                    self._add_finding("Files", f"{len(exec_like)} executable files", min(len(exec_like)//5, 3))
                if su_like:
                    self._add_finding("Files", f"{len(su_like)} suspicious binaries", 5)
                if script_like:
                    self._add_finding("Files", f"{len(script_like)} scripts found", min(len(script_like)//3, 3))
                if macho_count:
                    self._add_finding("Files", f"{macho_count} Mach-O files", 0)

                fwdir_path = os.path.join(app_path, "Frameworks")
                if os.path.exists(fwdir_path):
                    for item in os.listdir(fwdir_path):
                        if item.endswith(".framework"):
                            fw_name = item.split(".")[0]
                            if fw_name in PRIVATE_FRAMEWORKS:
                                self._add_finding("Binary", f"Bundled Private Framework: {item}", 4)
                                self.details["private_frameworks"].append(item)

                main_bin_name = self.details["info"].get("CFBundleExecutable", None)
                main_bin_path = None
                if main_bin_name:
                    main_bin_path = os.path.join(app_path, main_bin_name)

                if main_bin_path and os.path.exists(main_bin_path):
                    h = sha256_of_file(main_bin_path)
                    self._add_finding("Main Binary", f"SHA256: {h}", 0)
                    size = os.path.getsize(main_bin_path)
                    if size > 50 * 1024 * 1024:
                        self._add_finding("Binary Size", f"{size//1024//1024} MB (large binary)", 2)
                else:
                    self._add_finding("Binary", "Main executable not found", 2)

                self.details["extracted_urls"] = sorted(list(set(self.details["extracted_urls"])))
                self.details["suspicious_strings"] = sorted(list(set(self.details["suspicious_strings"])))
                
                if self.details["extracted_urls"]:
                    self._add_finding("Network", f"{len(self.details['extracted_urls'])} URLs found", 1)
                if self.details["suspicious_strings"]:
                    self._add_finding("Binary", f"{len(self.details['suspicious_strings'])} suspicious strings", 3)
                
                self.details["scanned_at"] = datetime.datetime.utcnow().isoformat() + "Z"
                self.details["risk_score"] = self.score

        except Exception as e:
            self._add_finding("Fatal Error", str(e), 10)
        finally:
            pass

    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

class AppUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AppShield — Enhanced IPA Analyzer")
        self.root.geometry("1100x700")
        self.root.configure(bg="#2E2E2E")
        
        self.analyzer_details = {}
        self.analyzer_findings = []
        self.FG = "#E0E0E0"

        self.setup_font_and_style()
        
        top_frame = ttk.Frame(self.root, style="TFrame")
        top_frame.pack(fill="x", padx=12, pady=(12, 8))
        
        ttk.Label(top_frame, text="IPA File:", style="TLabel").pack(side="left")
        
        self.path_var = tk.StringVar()
        self.entry = ttk.Entry(top_frame, textvariable=self.path_var, width=70)
        self.entry.pack(side="left", fill="x", expand=True, padx=6)
        
        ttk.Button(top_frame, text="Browse...", command=self.browse, style="TButton").pack(side="left")
        ttk.Button(top_frame, text="Analyze", command=self.analyze, style="Accent.TButton").pack(side="left", padx=6)
        ttk.Button(top_frame, text="Clear", command=self.clear_results, style="TButton").pack(side="left")
        
        self.score_label = ttk.Label(top_frame, text="Risk: N/A", font=(self.default_font[0], 12, 'bold'), style="TLabel")
        self.score_label.pack(side="right", padx=(10, 0))

        self.main_pane = ttk.PanedWindow(self.root, orient="horizontal")
        self.main_pane.pack(fill="both", expand=True, padx=12, pady=8)

        left_frame = ttk.Frame(self.main_pane, width=400)
        ttk.Label(left_frame, text="Findings", font=(self.default_font[0], 11, 'bold'), style="TLabel").pack(anchor="w", pady=(0, 5))
        
        self.tree = ttk.Treeview(left_frame, columns=("cat", "info"), show="headings", height=30)
        self.tree.heading("cat", text="Category")
        self.tree.heading("info", text="Detail")
        self.tree.column("cat", width=120, stretch=False)
        self.tree.column("info", width=250, stretch=True)
        
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        tree_scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        
        self.main_pane.add(left_frame, weight=2)

        right_frame = ttk.Frame(self.main_pane, width=600)
        ttk.Label(right_frame, text="Analysis Details", font=(self.default_font[0], 11, 'bold'), style="TLabel").pack(anchor="w", pady=(0, 5))
        
        self.notebook = ttk.Notebook(right_frame, style="TNotebook")
        
        self.summary_tab = self.create_text_tab("Summary")
        
        self.file_tree_tab = ttk.Frame(self.notebook, style="TFrame")
        self.file_tree = ttk.Treeview(self.file_tree_tab, columns=("size",), show="tree headings")
        self.file_tree.heading("#0", text="File/Directory")
        self.file_tree.heading("size", text="Info")
        self.file_tree.column("size", width=100, stretch=False)
        
        file_tree_scroll = ttk.Scrollbar(self.file_tree_tab, orient="vertical", command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=file_tree_scroll.set)
        file_tree_scroll.pack(side="right", fill="y")
        self.file_tree.pack(fill="both", expand=True)
        self.notebook.add(self.file_tree_tab, text="File Tree")
        
        self.info_tab = self.create_text_tab("Info.plist")
        
        self.ent_tab = self.create_text_tab("Entitlements")
        
        self.strings_tab = self.create_text_tab("Strings & URLs")
        
        self.notebook.pack(fill="both", expand=True)
        self.main_pane.add(right_frame, weight=3)

        bottom_frame = ttk.Frame(self.root, style="TFrame")
        bottom_frame.pack(fill="x", padx=12, pady=8)
        
        ttk.Button(bottom_frame, text="Credits", command=self.show_credits).pack(side="left")
        ttk.Button(bottom_frame, text="Export Details (JSON)", command=self.export_json).pack(side="right")
        ttk.Button(bottom_frame, text="Save Findings (TXT)", command=self.save_findings).pack(side="right", padx=10)

    def create_text_tab(self, name):
        frame = ttk.Frame(self.notebook, style="TFrame")
        
        txt_scroll = ttk.Scrollbar(frame, orient="vertical")
        txt = tk.Text(frame, wrap="word", bg="#1E1E1E", fg="#D4D4D4",
                      insertbackground="#D4D4D4", selectbackground="#3A3D41",
                      font=("Courier", 10), yscrollcommand=txt_scroll.set,
                      padx=5, pady=5, bd=0, highlightthickness=0)
        txt_scroll.config(command=txt.yview)
        
        txt_scroll.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        
        self.notebook.add(frame, text=name)
        return txt

    def setup_font_and_style(self):
        try:
            font_families = tkfont.families()
            if "Inter" in font_families:
                self.default_font = ("Inter", 10)
            elif "Segoe UI" in font_families:
                self.default_font = ("Segoe UI", 9)
            elif "Helvetica" in font_families:
                self.default_font = ("Helvetica", 10)
            else:
                self.default_font = ("Arial", 10)
        except:
            self.default_font = ("Arial", 10)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except:
            pass

        BG = "#2E2E2E"
        self.FG = "#E0E0E0"
        INACTIVE_BG = "#252526"
        INACTIVE_FG = "#A0A0A0"
        ACCENT = "#007ACC"
        SELECT_BG = "#3A3D41"
        BORDER = "#3E3E3E"

        style.configure(".",
                        background=BG,
                        foreground=self.FG,
                        fieldbackground=INACTIVE_BG,
                        troughcolor=INACTIVE_BG,
                        borderwidth=0,
                        highlightthickness=0,
                        font=self.default_font)

        style.map(".",
                  foreground=[('disabled', INACTIVE_FG), ('active', self.FG)],
                  background=[('disabled', INACTIVE_BG), ('active', ACCENT)],
                  fieldbackground=[('disabled', INACTIVE_BG)])

        style.configure("TFrame", background=BG)
        
        style.configure("TLabel", background=BG, foreground=self.FG)

        style.configure("TButton", padding=6, background=INACTIVE_BG, foreground=self.FG)
        style.map("TButton", background=[('active', SELECT_BG)])
        
        style.configure("Accent.TButton", padding=6, background=ACCENT, foreground="#FFFFFF")
        style.map("Accent.TButton", background=[('active', "#005a9e")])

        style.configure("TEntry", padding=5, bordercolor=BORDER, borderwidth=1,
                        insertcolor=self.FG)
        style.map("TEntry",
                  bordercolor=[('focus', ACCENT)],
                  fieldbackground=[('focus', INACTIVE_BG)])

        style.configure("Treeview",
                        rowheight=25,
                        fieldbackground=INACTIVE_BG,
                        background=INACTIVE_BG,
                        foreground=self.FG)
        style.map("Treeview",
                  background=[('selected', ACCENT)],
                  foreground=[('selected', "#FFFFFF")])
        style.configure("Treeview.Heading",
                        font=(self.default_font[0], self.default_font[1], 'bold'),
                        background=INACTIVE_BG,
                        foreground=self.FG,
                        padding=5)
        style.map("Treeview.Heading", background=[('active', SELECT_BG)])
        
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=INACTIVE_BG,
                        foreground=INACTIVE_FG,
                        padding=(10, 5),
                        font=(self.default_font[0], 10))
        style.map("TNotebook.Tab",
                  background=[('selected', BG)],
                  foreground=[('selected', self.FG)])

        self.root.option_add("*Font", self.default_font)
        self.root.option_add("*TCombobox*Listbox*Font", self.default_font)

    def browse(self):
        p = filedialog.askopenfilename(filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")])
        if p:
            self.path_var.set(p)
            self.clear_results()

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.file_tree.delete(*self.file_tree.get_children())
        
        self.summary_tab.config(state="normal")
        self.info_tab.config(state="normal")
        self.ent_tab.config(state="normal")
        self.strings_tab.config(state="normal")
        
        self.summary_tab.delete("1.0", "end")
        self.info_tab.delete("1.0", "end")
        self.ent_tab.delete("1.0", "end")
        self.strings_tab.delete("1.0", "end")

        self.summary_tab.config(state="disabled")
        self.info_tab.config(state="disabled")
        self.ent_tab.config(state="disabled")
        self.strings_tab.config(state="disabled")
        
        self.score_label.config(text="Risk: N/A", foreground=self.FG)
        self.analyzer_details = {}
        self.analyzer_findings = []

    def _populate_file_tree(self, parent_node, tree_dict):
        for name, content in sorted(tree_dict.items()):
            if isinstance(content, dict):
                node = self.file_tree.insert(parent_node, "end", text=name, open=False)
                self._populate_file_tree(node, content)
            else:
                self.file_tree.insert(parent_node, "end", text=name, values=("File",))

    def _insert_text(self, text_widget, content):
        text_widget.config(state="normal")
        text_widget.delete("1.0", "end")
        text_widget.insert("1.0", content)
        text_widget.config(state="disabled")

    def analyze(self):
        p = self.path_var.get().strip()
        if not p or not os.path.exists(p):
            messagebox.showerror("Error", "Select a valid IPA file")
            return
        
        self.clear_results()
        self.root.update_idletasks()
        
        try:
            analyzer = Analyzer(p)
            analyzer.run()

            self.analyzer_details = analyzer.details
            self.analyzer_findings = analyzer.findings
            
            for cat, info in analyzer.findings:
                self.tree.insert("", "end", values=(cat, info))
            
            info = analyzer.details.get("info", {})
            ent = analyzer.details.get("entitlements", {})
            
            summary_text = (
                f"App Name: {info.get('CFBundleName', 'N/A')}\n"
                f"Bundle ID: {info.get('CFBundleIdentifier', 'N/A')}\n"
                f"Version: {info.get('CFBundleShortVersionString', 'N/A')}\n\n"
                f"Risk Score: {analyzer.score}\n"
                f"Scanned: {analyzer.details.get('scanned_at', 'N/A')}\n\n"
                f"--- Key Details ---\n"
                f"Entitlements Source: {analyzer.details.get('entitlements_source', 'N/A')}\n"
                f"Total Files in .app: {len(analyzer.details.get('files', []))}\n"
                f"Mach-O Files: {sum(1 for f in analyzer.findings if f[0] == 'Files' and 'Mach-O' in f[1])}\n"
                f"Suspicious Strings: {len(analyzer.details.get('suspicious_strings', []))}\n"
                f"Found URLs: {len(analyzer.details.get('extracted_urls', []))}\n"
            )
            self._insert_text(self.summary_tab, summary_text)
            
            self._populate_file_tree("", analyzer.details.get("file_tree", {}))

            self._insert_text(self.info_tab, json.dumps(info, indent=2))
            
            self._insert_text(self.ent_tab, json.dumps(ent, indent=2))
            
            strings_text = "--- SUSPICIOUS STRINGS ---\n"
            strings_text += "\n".join(analyzer.details.get("suspicious_strings", ["None"]))
            strings_text += "\n\n--- EXTRACTED URLs ---\n"
            strings_text += "\n".join(analyzer.details.get("extracted_urls", ["None"]))
            self._insert_text(self.strings_tab, strings_text)
            
            label, color = self.risk_label_color(analyzer.score)
            self.score_label.config(text=f"Risk: {label} ({analyzer.score})", foreground=color)

        except Exception as e:
            messagebox.showerror("Analysis Failed", f"An unexpected error occurred: {e}")
        finally:
            if 'analyzer' in locals():
                analyzer.cleanup()

    def risk_label_color(self, score):
        if score <= 5:
            return ("Low", "#4CAF50")
        if score <= 15:
            return ("Moderate", "#FFC107")
        if score <= 30:
            return ("High", "#FF9800")
        return ("Critical", "#F44336")

    def save_findings(self):
        if not self.analyzer_findings:
            messagebox.showinfo("Info", "No findings to save. Run an analysis first.")
            return
        
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not p:
            return
        
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(f"AppShield IPA Analysis Report\n")
                f.write(f"File: {self.path_var.get()}\n")
                f.write(f"Risk Score: {self.analyzer_details.get('risk_score', 'N/A')}\n")
                f.write(f"Scanned: {self.analyzer_details.get('scanned_at', 'N/A')}\n")
                f.write("-" * 30 + "\n\n")
                
                for cat, info in self.analyzer_findings:
                    f.write(f"[{cat}]\t{info}\n")
            
            messagebox.showinfo("Saved", f"Findings saved to {p}")
        except Exception as e:
            messagebox.showerror("Save Failed", f"Could not save file: {e}")

    def export_json(self):
        if not self.analyzer_details:
            messagebox.showinfo("Info", "No details to export. Run an analysis first.")
            return

        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not p:
            return
        
        full_report = {
            "summary": {
                "file": self.path_var.get(),
                "risk_score": self.analyzer_details.get('risk_score'),
                "scanned_at": self.analyzer_details.get('scanned_at')
            },
            "findings": [{"category": f[0], "detail": f[1]} for f in self.analyzer_findings],
            "details": self.analyzer_details
        }
        
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(full_report, f, indent=2)
            
            messagebox.showinfo("Exported", f"Full analysis report exported to {p}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export JSON: {e}")

    def show_credits(self):
        title = "Credits"
        message = (
            "ZodaciOS - Developer\n\n"
            "https://github.com/ZodaciOS - My github account\n"
            "https://github.com/ZodaciOS/AppShield - the repo of this script\n\n"
            "Please follow me & star the repo. Thanks!"
        )
        messagebox.showinfo(title, message)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    AppUI().run()
