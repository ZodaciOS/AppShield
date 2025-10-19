import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import zipfile, os, plistlib, tempfile, shutil, hashlib, stat, datetime

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
)

HIGH_RISK_KEYS = (
    "get-task-allow",
    "keychain-access-groups",
    "com.apple.developer.kernel-extension",
    "com.apple.private",
    "com.apple.developer.device-lockdown",
)

EXECUTABLE_EXTS = (".dylib", ".so", ".framework", "")
SCRIPT_EXTS = (".sh", ".pl", ".py", ".rb", ".js", ".command")

def read_plist_bytes(data):
    try:
        return plistlib.loads(data)
    except Exception:
        try:
            txt = data.decode(errors="ignore")
            s = txt.find("<?xml")
            e = txt.find("</plist>")
            if s != -1 and e != -1:
                return plistlib.loads(txt[s:e+8].encode())
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
        self.details = {}
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
                    self.findings.append(("Error", "Payload/*.app not found"))
                    self.score += 3
                    return
                self.details["app_path"] = app_path
                info_plist = os.path.join(app_path, "Info.plist")
                mobileprov = os.path.join(app_path, "embedded.mobileprovision")
                ent_xcent = os.path.join(app_path, "archived-expanded-entitlements.xcent")
                files = []
                for root, dirs, fnames in os.walk(app_path):
                    for f in fnames:
                        rel = os.path.relpath(os.path.join(root, f), app_path)
                        files.append(rel)
                self.details["files"] = files
                if os.path.exists(info_plist):
                    try:
                        with open(info_plist, "rb") as f:
                            info = plistlib.load(f)
                        self.details["info"] = info
                        bid = info.get("CFBundleIdentifier", "unknown")
                        bn = info.get("CFBundleName", info.get("CFBundleDisplayName", "unknown"))
                        ver = info.get("CFBundleShortVersionString", info.get("CFBundleVersion", "unknown"))
                        self.findings.append(("App", f"{bn} ({bid}) v{ver}"))
                        if info.get("UIFileSharingEnabled"):
                            self.findings.append(("Sandbox", "UIFileSharingEnabled = true (file sharing enabled)"))
                            self.score += 2
                        ats = info.get("NSAppTransportSecurity")
                        if ats and ats.get("NSAllowsArbitraryLoads"):
                            self.findings.append(("Network", "NSAllowsArbitraryLoads = true (ATS disabled)"))
                            self.score += 2
                        if info.get("LSApplicationQueriesSchemes"):
                            self.findings.append(("Info", f"URL schemes allowed: {len(info.get('LSApplicationQueriesSchemes'))}"))
                        perms = [k for k in info.keys() if k.endswith("UsageDescription")]
                        for p in perms:
                            self.findings.append(("Permission", f"{p}: {info.get(p)}"))
                    except Exception:
                        self.findings.append(("Warning", "Info.plist present but could not be parsed"))
                        self.score += 1
                else:
                    self.findings.append(("Warning", "Info.plist not found"))
                    self.score += 2
                ent = {}
                if os.path.exists(ent_xcent):
                    try:
                        with open(ent_xcent, "rb") as f:
                            ent = plistlib.load(f)
                        self.details["entitlements_source"] = "archived-expanded-entitlements.xcent"
                    except Exception:
                        ent = {}
                elif os.path.exists(mobileprov):
                    try:
                        with open(mobileprov, "rb") as f:
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
                        kl = k.lower()
                        if any(sub in k for sub in SUSPICIOUS_ENTITLEMENT_SUBSTRINGS):
                            self.findings.append(("Entitlement", f"{k} present"))
                            self.score += 3
                        if "get-task-allow" in k and v:
                            self.findings.append(("Entitlement", "get-task-allow = true (debuggable)"))
                            self.score += 4
                        if "keychain-access-groups" in k:
                            self.findings.append(("Keychain", str(v)))
                            if isinstance(v, (list, tuple)):
                                for g in v:
                                    if "*" in str(g):
                                        self.findings.append(("Keychain", "Wildcard in keychain-access-groups detected"))
                                        self.score += 3
                        if isinstance(v, str) and "*" in v and v.count("*")>0:
                            self.findings.append(("Entitlement", f"{k} contains wildcard: {v}"))
                            self.score += 2
                        if "application-identifier" in k:
                            aid = v
                            if isinstance(aid, str) and aid.endswith("*"):
                                self.findings.append(("Provision", f"Application identifier uses wildcard: {aid}"))
                                self.score += 3
                else:
                    self.findings.append(("Entitlements", "No entitlements found in common locations"))
                    self.score += 2
                frameworks = []
                fwdir = os.path.join(app_path, "Frameworks")
                if os.path.exists(fwdir):
                    for item in os.listdir(fwdir):
                        frameworks.append(item)
                if frameworks:
                    self.findings.append(("Frameworks", ", ".join(frameworks)))
                    self.score += min(len(frameworks), 3)
                exec_like = []
                su_like = []
                script_like = []
                macho_count = 0
                large_files = []
                with zipfile.ZipFile(self.ipa_path, "r") as z:
                    for zinfo in z.infolist():
                        if not zinfo.filename.startswith(os.path.join("Payload", os.path.basename(app_path))):
                            continue
                        name = os.path.basename(zinfo.filename)
                        mode = zip_entry_unix_mode(zinfo)
                        is_exec = bool(mode & stat.S_IXUSR)
                        is_setuid = bool(mode & stat.S_ISUID)
                        if is_setuid:
                            su_like.append(zinfo.filename)
                            self.score += 5
                        if is_exec:
                            exec_like.append(zinfo.filename)
                        lower = zinfo.filename.lower()
                        if lower.endswith(SCRIPT_EXTS):
                            script_like.append(zinfo.filename)
                            self.score += 2
                        try:
                            raw = z.read(zinfo.filename)
                        except Exception:
                            raw = b""
                        if looks_macho(raw):
                            macho_count += 1
                            if len(raw) > 5 * 1024 * 1024:
                                large_files.append((zinfo.filename, zinfo.file_size))
                        if any(s in lower for s in ("su", "sudo", "dropbear", "sshd", "ssh")) and (lower.endswith("") or lower.endswith(".bin") or "bin" in lower):
                            su_like.append(zinfo.filename)
                if exec_like:
                    self.findings.append(("Executable entries", f"{len(exec_like)} executable-like files"))
                    self.score += min(len(exec_like), 3)
                if su_like:
                    for s in su_like[:10]:
                        self.findings.append(("Suspicious binary", s))
                    self.score += 5
                if script_like:
                    self.findings.append(("Scripts", f"{len(script_like)} script-like files"))
                    self.score += min(len(script_like), 3)
                if macho_count:
                    self.findings.append(("Mach-O", f"{macho_count} Mach-O objects detected"))
                if large_files:
                    for lf in large_files[:10]:
                        self.findings.append(("Large file", f"{lf[0]} size={lf[1]//1024}KB"))
                        self.score += 1
                main_bin = None
                for f in os.listdir(app_path):
                    fp = os.path.join(app_path, f)
                    if os.path.isfile(fp) and not f.endswith((".plist", ".png", ".storyboardc", ".car")):
                        try:
                            with open(fp, "rb") as fh:
                                head = fh.read(4)
                            if looks_macho(head):
                                main_bin = fp
                                break
                        except Exception:
                            continue
                if main_bin:
                    h = sha256_of_file(main_bin)
                    self.findings.append(("Main binary SHA256", h))
                    try:
                        size = os.path.getsize(main_bin)
                        if size > 50 * 1024 * 1024:
                            self.findings.append(("Binary size", f"{size//1024//1024} MB (large binary)"))
                            self.score += 2
                    except Exception:
                        pass
                else:
                    self.findings.append(("Binary", "Main Mach-O binary not auto-detected"))
                    self.score += 2
                self.details["scanned_at"] = datetime.datetime.utcnow().isoformat() + "Z"
        finally:
            pass
    def cleanup(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

class AppUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AppShield — IPA Analyzer")
        self.root.geometry("980x680")
        self.root.configure(bg="#121212")
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except:
            pass
        style.configure("TButton", padding=6)
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=12, pady=8)
        self.path_var = tk.StringVar()
        ttk.Label(top, text="IPA:", width=6).pack(side="left")
        self.entry = ttk.Entry(top, textvariable=self.path_var, width=80)
        self.entry.pack(side="left", padx=6)
        ttk.Button(top, text="Browse", command=self.browse).pack(side="left")
        ttk.Button(top, text="Analyze", command=self.analyze).pack(side="left", padx=6)
        self.score_label = ttk.Label(top, text="Risk: N/A")
        self.score_label.pack(side="right")
        mid = ttk.Frame(self.root)
        mid.pack(fill="both", expand=True, padx=12, pady=8)
        left = ttk.Frame(mid, width=360)
        left.pack(side="left", fill="y")
        ttk.Label(left, text="Findings").pack(anchor="w")
        self.tree = ttk.Treeview(left, columns=("cat","info"), show="headings", height=30)
        self.tree.heading("cat", text="Category")
        self.tree.heading("info", text="Detail")
        self.tree.column("cat", width=140)
        self.tree.column("info", width=200)
        self.tree.pack(fill="both", expand=True)
        right = ttk.Frame(mid)
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        ttk.Label(right, text="Details").pack(anchor="w")
        self.detail_txt = tk.Text(right, wrap="word", bg="#111", fg="#eee")
        self.detail_txt.pack(fill="both", expand=True)
        bottom = ttk.Frame(self.root)
        bottom.pack(fill="x", padx=12, pady=8)
        ttk.Button(bottom, text="Save Findings", command=self.save_findings).pack(side="right")
    def browse(self):
        p = filedialog.askopenfilename(filetypes=[("IPA files","*.ipa"),("All files","*.*")])
        if p:
            self.path_var.set(p)
    def analyze(self):
        p = self.path_var.get().strip()
        if not p or not os.path.exists(p):
            messagebox.showerror("Error","Select valid IPA")
            return
        self.tree.delete(*self.tree.get_children())
        self.detail_txt.delete("1.0","end")
        analyzer = Analyzer(p)
        analyzer.run()
        score = analyzer.score
        for cat, info in analyzer.findings:
            self.tree.insert("", "end", values=(cat, info))
        det = ""
        info = analyzer.details.get("info")
        if info:
            det += "Info.plist:\n"
            for k,v in info.items():
                det += f"{k}: {v}\n"
            det += "\n"
        ent = analyzer.details.get("entitlements")
        if ent:
            det += "Entitlements:\n"
            for k,v in ent.items():
                det += f"{k}: {v}\n"
            det += "\n"
        files = analyzer.details.get("files", [])
        det += f"Total files in .app: {len(files)}\n\n"
        det += f"Scanned at: {analyzer.details.get('scanned_at')}\n"
        self.detail_txt.insert("1.0", det)
        label, color = self.risk_label_color(score)
        self.score_label.config(text=f"Risk: {label} ({score})", foreground=color)
        analyzer.cleanup()
    def risk_label_color(self, score):
        if score <= 2:
            return ("Low", "green")
        if score <= 6:
            return ("Moderate", "orange")
        return ("High", "red")
    def save_findings(self):
        if not self.tree.get_children():
            messagebox.showinfo("Info","No findings to save")
            return
        p = filedialog.asksaveasfilename(defaultextension=".txt")
        if not p:
            return
        with open(p, "w", encoding="utf-8") as f:
            for iid in self.tree.get_children():
                vals = self.tree.item(iid)["values"]
                f.write(f"{vals[0]}: {vals[1]}\n")
        messagebox.showinfo("Saved", f"Findings saved to {p}")
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    AppUI().run()
