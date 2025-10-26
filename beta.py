# do not use this it is beta
import tkinter as tk
from tkinter import filedialog, ttk, messagebox, Menu, Text, simpledialog
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
import traceback
import string
import webbrowser
import platform
import threading
import queue
import subprocess
import struct

try:
    from PIL import Image, ImageTk, ImageDraw
except ImportError:
    messagebox.showerror("Missing Dependency", "Pillow library not found.\nPlease run 'pip install pillow' to enable image viewing and file icons.")

# --- Constants ---
SUSPICIOUS_ENTITLEMENT_SUBSTRINGS = (
    "com.apple.private", "com.apple.developer.kernel-extension", "com.apple.developer.device-lockdown",
    "com.apple.developer.networking.networkextension", "com.apple.developer.networking.vpn", "com.apple.security.cs",
    "com.apple.developer.in-app-payments", "com.apple.developer.facialrecognition", "com.apple.developer.healthkit",
    "com.apple.developer.homekit", "com.apple.developer.siri", "com.apple.developer.device-management",
    "com.apple.developer.kernel", "com.apple.developer.pass-type-identifiers", "com.apple.developer.contacts.notes",
    "com.apple.developer.location.always", "com.apple.developer.family-controls",
    "com.apple.developer.payment-pass-provisioning", "com.apple.developer.push-to-talk",
    "com.apple.security.network.server", "com.apple.security.network.client",
)
HIGH_RISK_KEYS = (
    "get-task-allow", "keychain-access-groups", "com.apple.developer.kernel-extension", "com.apple.private",
    "com.apple.developer.device-lockdown", "com.apple.security.app-sandbox", "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection", "com.apple.security.cs.debugger",
)
JAILBREAK_STRINGS = (
    b"Cydia", b"Sileo", b"Zebra", b"unc0ver", b"Taurine", b"checkra1n", b"Frida", b"cycript", b"Cycript",
    b"Substrate", b"substrate", b"MSHookFunction", b"/bin/bash", b"/usr/sbin/sshd", b"/etc/apt",
    b"/Applications/Cydia.app", b"/Library/MobileSubstrate/MobileSubstrate.dylib", b"/usr/libexec/sftp-server",
    b"/usr/bin/sshd", b"/var/cache/apt/", b"/var/lib/apt", b"/var/lib/cydia", b"/var/log/syslog",
    b"/private/var/stash", b"/private/var/tmp/cydia.log", b"/private/var/lib/apt/", b"/Applications/FakeCarrier.app",
    b"/Applications/Filza.app", b"/Applications/iFile.app", b"/Applications/NewTerm.app",
    b"jbexec", b"launchctl", b"spawn", b"cynject", b"/usr/lib/libcycript.dylib"
)
SUSPICIOUS_IMPORTS = (
    b"_performTask", b"task_for_pid", b"performSelector", b"dlopen", b"dlsym", b"ptrace", b"sysctl",
    b"PT_DENY_ATTACH", b"isatty", b"getppid", b"fork", b"exit", b"syscall",
    b"KERN_PROC", b"P_TRACED", b"sysctlbyname", b"MobileGestalt", b"MGCopyAnswer",
    b"LSApplicationWorkspace", b"SpringBoardServices", b"SBS",
    b"UIWebView", b"objc_getClass", b"class_getInstanceMethod", b"method_exchangeImplementations",
    b"NSFileProtectionKey", b"DCAppAttestService"
)
WEAK_HASH_STRINGS = ( b"MD5", b"SHA1", b"CC_MD5", b"CC_SHA1")
SUSPICIOUS_DDNS = ( b".ddns.net", b".no-ip.com", b".duckdns.org", b".dynu.com", b".strangled.net", b".hopto.org")
TRACKING_LIBS = ( b"FirebaseAnalytics", b"AppsFlyer", b"Adjust", b"Mixpanel", b"Flurry", b"GoogleAnalytics", b"Segment", b"Amplitude", b"BranchMetrics", b"Kochava")
CRYPTO_LIBS = ( b"CommonCrypto", b"RNCryptor", b"SQLCipher", b"OpenSSL", b"libsodium", b"CryptoSwift")
SUSPICIOUS_FILE_EXTS = (".zip", ".rar", ".db", ".sql", ".sqlite", ".7z", ".tar", ".gz")
SCRIPT_EXTS = (".sh", ".pl", ".py", ".rb", ".js", ".command")
URL_REGEX = re.compile(rb'https?://[^\s"\'<>]+', re.IGNORECASE)
IP_REGEX = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
AWS_KEY_REGEX = re.compile(rb'(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')
GOOGLE_API_KEY_REGEX = re.compile(rb'AIza[0-9A-Za-z\\-_]{35}')
FACEBOOK_APP_ID_REGEX = re.compile(rb'fb[0-9]{13,}')
GENERIC_KEY_TOKEN_REGEX = re.compile(rb'(key|token|secret|password|bearer|auth)[=:\s"\']+[A-Za-z0-9+/=_-]{16,}', re.IGNORECASE)
NSUSERDEFAULTS_SENSITIVE_REGEX = re.compile(rb'NSUserDefaults.*(password|token|secret|key|credential|auth)', re.IGNORECASE)

MH_MAGIC_64 = 0xfeedfacf; MH_CIGAM_64 = 0xcffaedfe; LC_SEGMENT_64 = 0x19; LC_LOAD_DYLIB = 0xc; LC_ENCRYPTION_INFO_64 = 0x2C; PIE_FLAG = 0x00200000; NO_REEXPORTED_DYLIBS_FLAG = 0x01000000; HAS_TLV_DESCRIPTORS_FLAG = 0x08000000; STACK_GUARD_FLAG = 0x00008000

def read_plist_bytes(data):
    try: return plistlib.loads(data)
    except Exception:
        try:
            s_idx = data.find(b"<?xml"); e_idx = data.find(b"</plist>")
            if s_idx != -1 and e_idx != -1: return plistlib.loads(data[s_idx : e_idx + 8])
        except Exception: return None
    return None

def sha256_of_file(path):
    h = hashlib.sha256();
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        print(f"Error hashing file {path}: {e}")
        return "Error Hashing"

def zip_entry_unix_mode(zinfo):
    try: return (zinfo.external_attr >> 16) & 0xFFFF
    except Exception: return 0

def looks_macho(data):
    if len(data) < 4: return False
    magic = struct.unpack('<I', data[:4])[0]
    return magic in (0xfeedface, 0xcefaedfe, MH_MAGIC_64, MH_CIGAM_64, 0xcafebabe)

class Analyzer:
    def __init__(self, ipa_path, log_callback=None):
        self.ipa_path = ipa_path
        self.tmpdir = tempfile.mkdtemp()
        self.findings = []
        self.score = 0
        self.details = {
            "info": {}, "entitlements": {}, "files": [], "file_tree": {}, "extracted_urls": [], "extracted_ips": [],
            "jailbreak_strings": [], "suspicious_imports": [], "weak_hashes": [], "suspicious_ddns": [],
            "tracking_libs": [], "crypto_libs": [], "hardcoded_aws_keys": [], "hardcoded_google_keys": [],
            "hardcoded_fb_ids": [], "hardcoded_generic_secrets": [], "injected_dylibs": [],
            "private_frameworks": [], "clipboard_access_files": set(), "sysctl_anti_debug": set(),
            "syscall_usage": set(), "suspicious_files": [], "macho_details": {},
            "insecure_nsuserdefaults": set(), "anti_debug_exit": set()
        }
        self.log_callback = log_callback

    def _log(self, message):
        if self.log_callback:
            self.log_callback(f"{datetime.datetime.now().strftime('%H:%M:%S')} - {message}\n")

    def _add_finding(self, category, info, score_increase):
        self.findings.append((category, info))
        self.score += score_increase
        self._log(f"Finding [{category}]: {info} (+{score_increase})")

    def _scan_file_content(self, data, filename):
        try:
            for url in URL_REGEX.findall(data):
                url_str = url.decode(errors="ignore"); self.details["extracted_urls"].append(url_str)
                url_domain = url.split(b'/')[2] if b'/' in url else b''
                for ddns in SUSPICIOUS_DDNS:
                    if ddns in url_domain: self.details["suspicious_ddns"].append(url_str); break
            for ip in IP_REGEX.findall(data): self.details["extracted_ips"].append(ip.decode(errors="ignore"))
            for s_str in JAILBREAK_STRINGS:
                if s_str in data: self.details["jailbreak_strings"].append(s_str.decode(errors="ignore"))
            for s_imp in SUSPICIOUS_IMPORTS:
                if s_imp in data: self.details["suspicious_imports"].append(s_imp.decode(errors="ignore"))
            for s_hash in WEAK_HASH_STRINGS:
                if s_hash in data: self.details["weak_hashes"].append(s_hash.decode(errors="ignore"))
            for tracker in TRACKING_LIBS:
                if tracker in data: self.details["tracking_libs"].append(tracker.decode(errors="ignore"))
            for crypto in CRYPTO_LIBS:
                if crypto in data: self.details["crypto_libs"].append(crypto.decode(errors="ignore"))
            for aws_key in AWS_KEY_REGEX.findall(data): self.details["hardcoded_aws_keys"].append(aws_key.decode(errors="ignore"))
            for google_key in GOOGLE_API_KEY_REGEX.findall(data): self.details.setdefault("hardcoded_google_keys", []).append(google_key.decode(errors="ignore"))
            for fb_id in FACEBOOK_APP_ID_REGEX.findall(data): self.details.setdefault("hardcoded_fb_ids", []).append(fb_id.decode(errors="ignore"))
            for generic_secret in GENERIC_KEY_TOKEN_REGEX.findall(data): self.details.setdefault("hardcoded_generic_secrets", []).append(b" ".join(generic_secret).decode(errors='ignore'))
            if NSUSERDEFAULTS_SENSITIVE_REGEX.search(data): self.details["insecure_nsuserdefaults"].add(filename)
            if b"UIPasteboard" in data: self.details["clipboard_access_files"].add(filename)
            if b"sysctl" in data and (b"KERN_PROC" in data or b"P_TRACED" in data): self.details["sysctl_anti_debug"].add(filename)
            if b"syscall" in data and b"(" in data: self.details["syscall_usage"].add(filename)
            if b"exit(" in data and (b"PT_DENY_ATTACH" in data or b"sysctl" in data or b"isatty" in data): self.details["anti_debug_exit"].add(filename)
        except Exception as e: print(f"Error scanning file content {filename}: {e}\n{traceback.format_exc()}")

    def _analyze_macho(self, data, filename):
        details = {'arch': 'Unknown', 'pie': False, 'arc': False, 'stack_canary': False, 'encrypted': False, 'swift': False, 'bitcode': False}
        try:
            if not looks_macho(data): return details
            magic = struct.unpack('<I', data[:4])[0]; is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64); endian = '<' if magic in (0xfeedface, MH_MAGIC_64, 0xcafebabe) else '>'
            if is_64:
                details['arch'] = 'arm64/x86_64'; header_format = endian + 'I I I I I I I I'; header_size = struct.calcsize(header_format)
                if len(data) < header_size: return details
                magic_val, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(header_format, data[:header_size])
                CPU_TYPE_ARM64 = 0x0100000c; CPU_TYPE_X86_64 = 0x01000007
                if cputype == CPU_TYPE_ARM64: details['arch'] = 'arm64'
                elif cputype == CPU_TYPE_X86_64: details['arch'] = 'x86_64'
                details['pie'] = bool(flags & PIE_FLAG); details['arc'] = bool(flags & (NO_REEXPORTED_DYLIBS_FLAG | HAS_TLV_DESCRIPTORS_FLAG))
                offset = header_size
                for _ in range(ncmds):
                    if offset + 8 > len(data): break
                    cmd, cmdsize = struct.unpack(endian + 'II', data[offset:offset+8])
                    if cmdsize == 0 or offset + cmdsize > len(data): break
                    if cmd == LC_SEGMENT_64:
                         seg_name = data[offset+8:offset+24].split(b'\0', 1)[0].decode(errors='ignore')
                         if seg_name == '__TEXT':
                             if offset+68 > len(data): break # Check bounds before unpack
                             nsects = struct.unpack(endian + 'I', data[offset+64:offset+68])[0]
                             sect_offset = offset + 72
                             for _ in range(nsects):
                                 if sect_offset + 80 > len(data): break
                                 sect_name = data[sect_offset:sect_offset+16].split(b'\0', 1)[0]
                                 if sect_name == b'__swift5_typeref': details['swift'] = True; break
                                 sect_offset += 80
                         elif seg_name == '__LLVM':
                             if offset+68 > len(data): break
                             nsects = struct.unpack(endian + 'I', data[offset+64:offset+68])[0]
                             sect_offset = offset + 72
                             for _ in range(nsects):
                                 if sect_offset + 80 > len(data): break
                                 sect_name = data[sect_offset:sect_offset+16].split(b'\0', 1)[0]
                                 if sect_name == b'__bundle': details['bitcode'] = True; break
                                 sect_offset += 80
                    elif cmd == LC_ENCRYPTION_INFO_64:
                        if offset+20 > len(data): break
                        cryptoff, cryptsize, cryptid = struct.unpack(endian + 'III', data[offset+8:offset+20]); details['encrypted'] = (cryptid != 0)
                    elif cmd & 0x7FFFFFFF == 0x22:
                         if len(data) > offset + 16:
                             flavor, count = struct.unpack(endian + 'II', data[offset+8:offset+16])
                             if cmd & STACK_GUARD_FLAG: details['stack_canary'] = True
                    offset += cmdsize
            else: details['arch'] = 'armv7/i386'
        except Exception as e: self._log(f"WARNING: Mach-O parsing error for {filename}: {e}")
        finally: self.details["macho_details"][filename] = details; return details

    def run(self):
        try:
            self._log("Starting analysis..."); self._log(f"IPA Path: {self.ipa_path}"); self._log(f"Temp Dir: {self.tmpdir}")
            with zipfile.ZipFile(self.ipa_path, "r") as z:
                self._log("Extracting IPA archive..."); z.extractall(self.tmpdir); self._log("Extraction complete.")
                payload = os.path.join(self.tmpdir, "Payload"); app_path = None
                if os.path.exists(payload):
                    for it in os.listdir(payload):
                        if it.endswith(".app"): app_path = os.path.join(payload, it); break
                if not app_path: self._add_finding("Error", "Payload/*.app not found", 10); self._log("ERROR: Payload/*.app not found."); return
                self._log(f"Found app bundle: {os.path.basename(app_path)}"); self.details["app_path"] = app_path; app_name = os.path.basename(app_path); app_prefix = f"Payload/{app_name}/"
                info = {}; info_plist_path = os.path.join(app_path, "Info.plist")
                if os.path.exists(info_plist_path):
                    self._log("Parsing Info.plist...")
                    try:
                        with open(info_plist_path, "rb") as f: info = plistlib.load(f)
                        self.details["info"] = info; bid = info.get("CFBundleIdentifier", "unknown"); bn = info.get("CFBundleName", info.get("CFBundleDisplayName", "unknown")); ver = info.get("CFBundleShortVersionString", info.get("CFBundleVersion", "unknown")); self._add_finding("App", f"{bn} ({bid}) v{ver}", 0)
                        if info.get("UIFileSharingEnabled"): self._add_finding("Sandbox", "UIFileSharingEnabled = true (file sharing)", 2)
                        ats = info.get("NSAppTransportSecurity");
                        if ats and ats.get("NSAllowsArbitraryLoads"): self._add_finding("Network", "NSAllowsArbitraryLoads = true (ATS disabled)", 2)
                        if ats and ats.get("NSExceptionDomains"): self._add_finding("Network", f"ATS Exception Domains defined ({len(ats['NSExceptionDomains'])})", 0)
                        schemes = info.get("LSApplicationQueriesSchemes", []);
                        if len(schemes) > 50: self._add_finding("Privacy", f"Excessive URL Schemes Queries ({len(schemes)}). Fingerprinting?", 3)
                        elif len(schemes) > 0: self._add_finding("Info", f"URL schemes queried: {len(schemes)}", 0)
                        url_types = info.get("CFBundleURLTypes", []);
                        if len(url_types) > 10: self._add_finding("Suspicious", f"Excessive Custom URL Schemes ({len(url_types)} registered).", 2)
                        elif len(url_types) > 0: self._add_finding("Info", f"Custom URL schemes registered: {len(url_types)}", 0)
                        if info.get("UIBackgroundModes"): modes = ", ".join(info.get("UIBackgroundModes", [])); self._add_finding("Privacy", f"Background Modes: {modes}", 2)
                        perms = [k for k in info.keys() if k.endswith("UsageDescription")];
                        if len(perms) > 7: self._add_finding("Privacy", f"Excessive Permissions requested ({len(perms)}).", 3)
                        for p in perms: self._add_finding("Permission", f"{p}", 0)
                        exec_name = info.get("CFBundleExecutable", ""); app_name_base = app_name.replace(".app", "")
                        if exec_name and app_name_base != exec_name: self._add_finding("Tampering", f"Executable name mismatch: '{exec_name}' vs '{app_name_base}'", 3)
                        min_os = info.get("MinimumOSVersion", "99.0");
                        try:
                            if float(min_os.split('.')[0]) < 13: self._add_finding("Security", f"Outdated MinimumOSVersion: {min_os}", 1)
                        except: pass
                        if info.get("NSLocationDefaultAccuracyReduced") == False: self._add_finding("Privacy", "Requests Full Location Accuracy by default", 1)
                        if info.get("UIApplicationSceneManifest"): self._add_finding("Info", "Uses Scene Delegate / SwiftUI Lifecycle", 0)
                        elif info.get("UIMainStoryboardFile"): self._add_finding("Info", "Uses Storyboard / App Delegate Lifecycle", 0)
                        self._log("Info.plist parsing successful.")
                    except Exception as e: self._add_finding("Warning", f"Info.plist parse error: {e}", 2); self._log(f"WARNING: Info.plist parse error - {e}")
                else: self._add_finding("Warning", "Info.plist not found", 3); self._log("WARNING: Info.plist not found.")
                ent = {}; ent_xcent_path = os.path.join(app_path, "archived-expanded-entitlements.xcent"); mobileprov_path = os.path.join(app_path, "embedded.mobileprovision"); self._log("Searching for entitlements...")
                if os.path.exists(ent_xcent_path):
                    self._log("Found archived-expanded-entitlements.xcent, attempting parse...")
                    try:
                        with open(ent_xcent_path, "rb") as f: ent = plistlib.load(f); self.details["entitlements_source"] = "archived-expanded-entitlements.xcent"; self._log("Parsed entitlements from .xcent file.")
                    except Exception as e: ent = {}; self._log(f"WARNING: Failed to parse .xcent - {e}")
                if not ent and os.path.exists(mobileprov_path):
                    self._log("Found embedded.mobileprovision, attempting parse...")
                    try:
                        with open(mobileprov_path, "rb") as f: raw = f.read(); prov = read_plist_bytes(raw)
                        if prov: ent = prov.get("Entitlements", {}); self.details["entitlements_source"] = "embedded.mobileprovision"; self._log("Parsed entitlements from .mobileprovision file.")
                        else: self._log("WARNING: Could not parse .mobileprovision as plist.")
                    except Exception as e: ent = {}; self._log(f"WARNING: Failed to parse .mobileprovision - {e}")
                if ent:
                    self.details["entitlements"] = ent; self._log(f"Processing {len(ent)} entitlements...")
                    for k, v in ent.items():
                        if k in HIGH_RISK_KEYS:
                            if k == "get-task-allow" and v: self._add_finding("Entitlement", "get-task-allow = true (debuggable)", 5)
                            elif k == "com.apple.security.app-sandbox" and not v: self._add_finding("Entitlement", "App Sandbox = false (disabled!)", 5)
                            elif k.startswith("com.apple.security.cs") and v: self._add_finding("Entitlement", f"High Risk: {k} = {v}", 5)
                            else: self._add_finding("Entitlement", f"High Risk: {k} present", 4)
                        if any(sub in k for sub in SUSPICIOUS_ENTITLEMENT_SUBSTRINGS): self._add_finding("Entitlement", f"Suspicious: {k} present", 3)
                        if "keychain-access-groups" in k: self._add_finding("Keychain", str(v), 0);
                        if isinstance(v, (list, tuple)) and any("*" in str(g) for g in v): self._add_finding("Keychain", "Wildcard in keychain-access-groups", 3)
                        if isinstance(v, str) and "*" in v and "application-identifier" not in k: self._add_finding("Entitlement", f"Wildcard value in {k}: {v}", 2)
                        if "application-identifier" in k and isinstance(v, str) and "*" in v: self._add_finding("Provision", f"Wildcard App ID: {v}", 3)
                    if info:
                        prov_app_id = ent.get("application-identifier", "prov_missing"); info_bundle_id = info.get("CFBundleIdentifier", "info_missing")
                        if "*" not in prov_app_id and "." in prov_app_id:
                            prov_app_id_suffix = prov_app_id.split(".", 1)[1]
                            if prov_app_id_suffix != info_bundle_id: self._add_finding("Tampering", f"ID mismatch: Plist='{info_bundle_id}' vs Provision='{prov_app_id_suffix}'", 3)
                else: self._add_finding("Entitlements", "No entitlements found", 2); self._log("No entitlements found in common locations.")
                exec_like, su_like, script_like = [], [], []; macho_count = 0; file_tree = {}; found_dylibs = []; main_bin_data = b""; main_bin_name = self.details["info"].get("CFBundleExecutable", None); has_swiftui, has_watchkit, has_code_resources = False, False, False; self._log("Scanning files within the app bundle...")
                file_count = 0; macho_files = []
                for zinfo in z.infolist():
                    if not zinfo.filename.startswith(app_prefix) or zinfo.is_dir(): continue
                    file_count += 1; rel_path = zinfo.filename[len(app_prefix):];
                    if not rel_path: continue; self.details["files"].append(rel_path)
                    parts = rel_path.split("/"); node = file_tree;
                    for part in parts[:-1]: node = node.setdefault(part, {})
                    node[parts[-1]] = "file"; mode = zip_entry_unix_mode(zinfo);
                    if bool(mode & stat.S_IXUSR): exec_like.append(rel_path)
                    if bool(mode & stat.S_ISUID): su_like.append(rel_path); self._add_finding("Suspicious File", f"SetUID bit set: {rel_path}", 5)
                    lower = rel_path.lower();
                    if lower.endswith(SCRIPT_EXTS): script_like.append(rel_path)
                    if lower == "embedded.provisionprofile": self._add_finding("Tampering", "Found 'embedded.provisionprofile' (often from repackaging)", 2)
                    if lower == "_codesignature/coderesources": has_code_resources = True
                    if "swiftui.framework" in lower or "_concurrency" in lower: has_swiftui = True
                    if "watchkit.framework" in lower or rel_path.startswith("Watch/"): has_watchkit = True
                    if lower.endswith(".dylib"): self._add_finding("Binary", f"Bundled Dylib: {rel_path}", 0); found_dylibs.append(os.path.basename(rel_path).encode())
                    if any(s in lower for s in ("su", "sudo", "dropbear", "sshd")): su_like.append(rel_path)
                    if "/" not in rel_path and any(rel_path.endswith(ext) for ext in SUSPICIOUS_FILE_EXTS): self.details["suspicious_files"].append(rel_path); self._add_finding("Suspicious File", f"Found '{rel_path}' in app root", 2)
                    try: raw = z.read(zinfo.filename)
                    except Exception: raw = b""
                    if looks_macho(raw):
                        macho_count += 1; macho_files.append((rel_path, raw))
                        if main_bin_name and rel_path == main_bin_name: main_bin_data = raw
                        else: self._scan_file_content(raw, rel_path)
                    elif lower.endswith((".js", ".html")): self._scan_file_content(raw, rel_path)
                self._log(f"Scanned {file_count} files."); self.details["file_tree"] = file_tree
                if self.details["clipboard_access_files"]: self._add_finding("Privacy", f"Potential clipboard access ({len(self.details['clipboard_access_files'])} files)", 1)
                if self.details.get("sysctl_anti_debug"): self._add_finding("Anti-Debug", f"Sysctl anti-debug detected ({len(self.details['sysctl_anti_debug'])} files)", 3)
                if self.details.get("syscall_usage"): self._add_finding("Suspicious", f"Direct syscall usage detected ({len(self.details['syscall_usage'])} files)", 4)
                if self.details.get("anti_debug_exit"): self._add_finding("Anti-Debug", f"Potential anti-debug exit ({len(self.details['anti_debug_exit'])} files)", 2)
                if exec_like: self._add_finding("Files", f"{len(exec_like)} executable files", min(len(exec_like)//5, 3))
                if su_like: self._add_finding("Files", f"{len(su_like)} suspicious binaries", 5)
                if script_like: self._add_finding("Files", f"{len(script_like)} scripts found", min(len(script_like)//3, 3))
                if macho_count: self._add_finding("Files", f"{macho_count} Mach-O files", 0)
                if not has_code_resources: self._add_finding("Tampering", "_CodeSignature/CodeResources not found", 2)
                if has_swiftui: self._add_finding("Info", "Uses SwiftUI/Concurrency", 0)
                if has_watchkit: self._add_finding("Info", "Includes WatchKit components", 0)
                self._log("Analyzing Mach-O headers...")
                for path, data in macho_files:
                    macho_info = self._analyze_macho(data, path)
                    is_main = (path == main_bin_name); prefix = "Main Binary" if is_main else f"Mach-O ({os.path.basename(path)})"
                    if macho_info['arch'] != 'Unknown': self._add_finding(prefix, f"Arch: {macho_info['arch']}", 0)
                    if not macho_info['pie']: self._add_finding(prefix, "PIE Disabled (Security Risk)", 2 if is_main else 1)
                    if not macho_info['arc']: self._add_finding(prefix, "ARC Likely Disabled (Memory Risk)", 1)
                    if macho_info['encrypted']: self._add_finding(prefix, "App Store Encrypted", 0)
                    if macho_info['swift']: self._add_finding(prefix, "Contains Swift code", 0)
                    if macho_info['bitcode']: self._add_finding(prefix, "Contains Bitcode", 0)
                self._log("Analyzing main binary references...")
                if main_bin_data:
                    if found_dylibs:
                        for dylib_name in found_dylibs:
                            if dylib_name in main_bin_data: decoded_name = dylib_name.decode(errors="ignore"); self._add_finding("Injection", f"Main binary references '{decoded_name}'", 5); self.details["injected_dylibs"].append(decoded_name)
                    if not main_bin_name in self.details["macho_details"]: self._analyze_macho(main_bin_data, main_bin_name)
                    self._log("Scanning main binary content...")
                    self._scan_file_content(main_bin_data, main_bin_name)
                    h = hashlib.sha256(main_bin_data).hexdigest(); self._add_finding("Main Binary", f"SHA256: {h}", 0); size = len(main_bin_data)
                    if size > 50 * 1024 * 1024: self._add_finding("Binary Size", f"{size//1024//1024} MB (large binary)", 2)
                elif main_bin_name: self._add_finding("Warning", f"Main binary '{main_bin_name}' in Plist but not found in zip", 3); self._log(f"WARNING: Main binary '{main_bin_name}' not found.")
                else: self._add_finding("Binary", "Main executable not found", 2); self._log("WARNING: Main executable name not found in Info.plist.")
                fwdir_path = os.path.join(app_path, "Frameworks")
                if os.path.exists(fwdir_path):
                    self._log("Analyzing frameworks...")
                    for item in os.listdir(fwdir_path):
                        if item.endswith(".framework"): fw_name = item.split(".")[0];
                        if fw_name in PRIVATE_FRAMEWORKS: self._add_finding("Binary", f"Bundled Private Framework: {item}", 4); self.details["private_frameworks"].append(item)
                self._log("Aggregating results...")
                for k in ["extracted_urls", "extracted_ips", "jailbreak_strings", "suspicious_imports", "weak_hashes", "suspicious_ddns", "tracking_libs", "crypto_libs", "hardcoded_aws_keys", "hardcoded_google_keys", "hardcoded_fb_ids", "hardcoded_generic_secrets", "suspicious_files"]: self.details[k] = sorted(list(set(self.details[k])))
                if self.details["extracted_urls"]: self._add_finding("Network", f"{len(self.details['extracted_urls'])} URLs found", 0)
                if self.details["extracted_ips"]: self._add_finding("Network", f"{len(self.details['extracted_ips'])} IPs found", 0)
                if self.details["suspicious_ddns"]: self._add_finding("Network", f"Found {len(self.details['suspicious_ddns'])} suspicious DDNS domains (C2?)", 4)
                if self.details["jailbreak_strings"]: self._add_finding("Suspicious", f"{len(self.details['jailbreak_strings'])} jailbreak strings/paths", 3)
                if self.details["suspicious_imports"]: self._add_finding("Suspicious", f"{len(self.details['suspicious_imports'])} suspicious imports/functions", 3)
                if self.details["weak_hashes"]: self._add_finding("Security", f"{len(self.details['weak_hashes'])} weak hashes (MD5/SHA1)", 1)
                if self.details["tracking_libs"]: self._add_finding("Privacy", f"{len(self.details['tracking_libs'])} known tracking libraries detected", 2)
                if self.details["crypto_libs"]: self._add_finding("Info", f"{len(self.details['crypto_libs'])} encryption libraries detected", 0)
                if self.details["hardcoded_aws_keys"]: self._add_finding("Security", f"{len(self.details['hardcoded_aws_keys'])} potential hardcoded AWS keys found", 4)
                if self.details.get("hardcoded_google_keys"): self._add_finding("Security", f"{len(self.details['hardcoded_google_keys'])} potential hardcoded Google API keys found", 3)
                if self.details.get("hardcoded_fb_ids"): self._add_finding("Info", f"{len(self.details['hardcoded_fb_ids'])} Facebook App IDs found", 0)
                if self.details.get("hardcoded_generic_secrets"): self._add_finding("Security", f"{len(self.details['hardcoded_generic_secrets'])} potential hardcoded secrets found", 3)
                if self.details["suspicious_files"]: self._add_finding("Suspicious", f"{len(self.details['suspicious_files'])} potentially suspicious files in root", 2)
                if self.details["insecure_nsuserdefaults"]: self._add_finding("Security", f"Potential insecure NSUserDefaults usage ({len(self.details['insecure_nsuserdefaults'])} files)", 2)
                self.details["scanned_at"] = datetime.datetime.utcnow().isoformat() + "Z"; self.details["risk_score"] = self.score
                self._log("Analysis finished.")
        except Exception as e: self._add_finding("Fatal Error", f"{e.__class__.__name__}: {e}", 10); self._log(f"FATAL ERROR: {e}\n{traceback.format_exc()}"); traceback.print_exc()
        finally: pass

    def cleanup(self):
        try: shutil.rmtree(self.tmpdir, ignore_errors=True)
        except Exception as e: print(f"Error cleaning up temp directory {self.tmpdir}: {e}")

class AppUI:
    def __init__(self):
        self.root = tk.Tk(); self.root.title("AppShield — Enhanced IPA Analyzer"); self.root.geometry("1100x700"); self.root.configure(bg="#2E2E2E")
        self.analyzer_details = {}; self.analyzer_findings = []; self.FG = "#E0E0E0"; self.selected_file_path = ""; self.current_analyzer = None; self.warned_about_modifications = False; self.progress_window = None; self.log_text_widget = None; self.folder_icon = None; self.file_icon = None
        self.setup_font_and_style(); self.create_menu(); self.create_icons()
        top_frame = ttk.Frame(self.root, style="TFrame"); top_frame.pack(fill="x", padx=12, pady=(5, 8))
        ttk.Label(top_frame, text="IPA File:", style="TLabel").pack(side="left", padx=(0, 5))
        self.path_var = tk.StringVar(); self.entry = ttk.Entry(top_frame, textvariable=self.path_var, width=70, font=self.default_font); self.entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(top_frame, text="Browse...", command=self.browse, style="TButton").pack(side="left", padx=(0, 6))
        self.analyze_button = ttk.Button(top_frame, text="Analyze", command=self.analyze, style="Accent.TButton"); self.analyze_button.pack(side="left", padx=(0, 6))
        ttk.Button(top_frame, text="Clear", command=self.clear_results, style="TButton").pack(side="left")
        self.score_label = ttk.Label(top_frame, text="Risk: N/A", font=self.default_font_bold, style="TLabel"); self.score_label.pack(side="right", padx=(10, 0))
        self.main_pane = ttk.PanedWindow(self.root, orient="horizontal"); self.main_pane.pack(fill="both", expand=True, padx=12, pady=(0, 4))
        left_frame = ttk.Frame(self.main_pane); findings_header_frame = ttk.Frame(left_frame); findings_header_frame.pack(fill="x", pady=(0, 2)); ttk.Label(findings_header_frame, text="Findings", font=self.default_font_bold, style="TLabel").pack(side="left", anchor="w")
        self.findings_search_var = tk.StringVar(); self.findings_search_var.trace_add("write", self.filter_findings); findings_search = ttk.Entry(findings_header_frame, textvariable=self.findings_search_var, font=self.default_font, width=20); findings_search.pack(side="right", padx=(5,0)); ttk.Label(findings_header_frame, text="Filter:", style="TLabel").pack(side="right")
        self.tree = ttk.Treeview(left_frame, columns=("cat", "info"), show="headings", height=30); self.tree.heading("cat", text="Category"); self.tree.heading("info", text="Detail"); self.tree.column("cat", width=120, stretch=False, anchor="w"); self.tree.column("info", width=250, stretch=True, anchor="w")
        tree_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview); self.tree.configure(yscrollcommand=tree_scroll.set); tree_scroll.pack(side="right", fill="y", padx=(0,0)); self.tree.pack(side="left", fill="both", expand=True, padx=(0,0))
        self.findings_tree_menu = tk.Menu(self.root, tearoff=0); self.findings_tree_menu.add_command(label="Copy Value", command=self.copy_finding_value); self.tree.bind("<Button-3>", self.show_findings_menu)
        self.main_pane.add(left_frame, weight=35)
        right_frame = ttk.Frame(self.main_pane); ttk.Label(right_frame, text="Analysis Details", font=self.default_font_bold, style="TLabel").pack(anchor="w", pady=(0, 5))
        self.notebook = ttk.Notebook(right_frame, style="TNotebook")
        self.summary_tab = self.create_text_tab("Summary"); self.file_tree_tab = ttk.Frame(self.notebook, style="TFrame")
        self.file_search_var = tk.StringVar(); self.file_search_var.trace_add("write", self.search_files); search_entry = ttk.Entry(self.file_tree_tab, textvariable=self.file_search_var, font=self.default_font); search_entry.pack(fill="x", padx=1, pady=(2,1))
        self.file_tree = ttk.Treeview(self.file_tree_tab, columns=("path",), show="tree headings", displaycolumns=()); self.file_tree.heading("#0", text="File/Directory"); self.file_tree.column("#0", stretch=True, anchor='w')
        file_tree_scroll = ttk.Scrollbar(self.file_tree_tab, orient="vertical", command=self.file_tree.yview); self.file_tree.configure(yscrollcommand=file_tree_scroll.set); file_tree_scroll.pack(side="right", fill="y", padx=(0,0)); self.file_tree.pack(fill="both", expand=True, pady=(1,0), padx=(0,0))
        self.file_tree_menu = tk.Menu(self.root, tearoff=0); self.file_tree_menu.add_command(label="View File", command=self.view_file_tree_selection, state="disabled"); self.file_tree_menu.add_command(label="Edit File", command=self.edit_file_tree_selection, state="disabled"); self.file_tree_menu.add_command(label="View Strings", command=self.view_file_strings, state="disabled"); self.file_tree_menu.add_command(label="View as Hex", command=self.view_file_hex, state="disabled"); self.file_tree_menu.add_command(label="Get SHA256 Hash", command=self.get_file_hash, state="disabled"); self.file_tree_menu.add_command(label="Lookup Hash on VirusTotal", command=self.lookup_hash_vt, state="disabled"); self.file_tree_menu.add_separator(); self.file_tree_menu.add_command(label="Export Selected File", command=self.export_file_tree_selection, state="disabled"); self.file_tree.bind("<Button-3>", self.show_file_tree_menu)
        self.notebook.add(self.file_tree_tab, text="File Tree"); self.info_tab = self.create_text_tab("Info.plist"); self.ent_tab = self.create_text_tab("Entitlements"); self.strings_tab = self.create_text_tab("Strings & URLs")
        self.notebook.pack(fill="both", expand=True, pady=(0,0)); self.main_pane.add(right_frame, weight=65)
        self.status_var = tk.StringVar(); self.status_var.set("Ready"); status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w', style="TLabel"); status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=0, pady=0)
        bottom_frame = ttk.Frame(self.root, style="TFrame"); bottom_frame.pack(fill="x", padx=12, pady=(5, 8))
        ttk.Button(bottom_frame, text="Export Details (JSON)", command=self.export_json).pack(side="right", padx=(0, 0))
        ttk.Button(bottom_frame, text="Save Findings (TXT)", command=self.save_findings).pack(side="right", padx=(0, 6))

    def create_icons(self):
        try:
            folder_color = "#FFA500"; file_color = "#D3D3D3"; icon_size = (16, 16)
            folder_img = Image.new('RGBA', icon_size, (0, 0, 0, 0)); draw = ImageDraw.Draw(folder_img); draw.rectangle([(1, 3), (icon_size[0]-2, icon_size[1]-2)], outline=folder_color, width=1); draw.rectangle([(3, 1), (8, 5)], outline=folder_color, width=1); self.folder_icon = ImageTk.PhotoImage(folder_img)
            file_img = Image.new('RGBA', icon_size, (0, 0, 0, 0)); draw = ImageDraw.Draw(file_img); draw.rectangle([(2, 1), (icon_size[0]-2, icon_size[1]-2)], outline=file_color, width=1); draw.line([(icon_size[0]-5, 1), (icon_size[0]-5, 5), (icon_size[0]-2, 5)], fill=file_color, width=1); self.file_icon = ImageTk.PhotoImage(file_img)
        except NameError: self.folder_icon = None; self.file_icon = None
        except Exception as e: print(f"Error creating icons: {e}"); self.folder_icon = None; self.file_icon = None

    def create_menu(self):
        menubar = Menu(self.root); self.root.config(menu=menubar)
        file_menu = Menu(menubar, tearoff=0, background="#252526", foreground="#E0E0E0", activebackground="#3A3D41", activeforeground="#E0E0E0", font=self.default_font); menubar.add_cascade(label="File", menu=file_menu); file_menu.add_command(label="Repack Unsigned IPA...", command=self.repackage_ipa); file_menu.add_command(label="Repack Signed IPA...", command=self.repackage_signed_ipa); file_menu.add_command(label="Open Temp Folder", command=self.open_temp_folder); file_menu.add_separator(); file_menu.add_command(label="Exit", command=self.root.quit)
        view_menu = Menu(menubar, tearoff=0, background="#252526", foreground="#E0E0E0", activebackground="#3A3D41", activeforeground="#E0E0E0", font=self.default_font); menubar.add_cascade(label="View", menu=view_menu); view_menu.add_command(label="Expand All Findings", command=lambda: self.expand_collapse_all(self.tree, True)); view_menu.add_command(label="Collapse All Findings", command=lambda: self.expand_collapse_all(self.tree, False)); view_menu.add_separator(); view_menu.add_command(label="Expand All Files", command=lambda: self.expand_collapse_all(self.file_tree, True)); view_menu.add_command(label="Collapse All Files", command=lambda: self.expand_collapse_all(self.file_tree, False))
        tools_menu = Menu(menubar, tearoff=0, background="#252526", foreground="#E0E0E0", activebackground="#3A3D41", activeforeground="#E0E0E0", font=self.default_font); menubar.add_cascade(label="Tools", menu=tools_menu); tools_menu.add_command(label="Generate Summary Report", command=self.generate_summary_report); tools_menu.add_command(label="Entitlement Explorer", command=self.show_entitlement_explorer)
        settings_menu = Menu(menubar, tearoff=0, background="#252526", foreground="#E0E0E0", activebackground="#3A3D41", activeforeground="#E0E0E0", font=self.default_font); menubar.add_cascade(label="Settings", menu=settings_menu); settings_menu.add_command(label="Reset Edit Warning", command=self.reset_edit_warning)
        help_menu = Menu(menubar, tearoff=0, background="#252526", foreground="#E0E0E0", activebackground="#3A3D41", activeforeground="#E0E0E0", font=self.default_font); menubar.add_cascade(label="Help", menu=help_menu); help_menu.add_command(label="Getting Started", command=self.show_getting_started); help_menu.add_separator(); help_menu.add_command(label="Credits", command=self.show_credits); help_menu.add_command(label="View GitHub Profile", command=lambda: webbrowser.open("https://github.com/ZodaciOS")); help_menu.add_command(label="View AppShield Repo", command=lambda: webbrowser.open("https://github.com/ZodaciOS/AppShield")); help_menu.add_command(label="Report Issues or Bugs", command=lambda: webbrowser.open("https://github.com/ZodaciOS/AppShield/issues"))

    def create_text_tab(self, name):
        frame = ttk.Frame(self.notebook, style="TFrame"); txt_scroll_y = ttk.Scrollbar(frame, orient="vertical"); txt_scroll_x = ttk.Scrollbar(frame, orient="horizontal"); txt = tk.Text(frame, wrap="none", bg="#1E1E1E", fg="#D4D4D4", insertbackground="#D4D4D4", selectbackground="#3A3D41", font=("Courier", 10), yscrollcommand=txt_scroll_y.set, xscrollcommand=txt_scroll_x.set, padx=5, pady=5, bd=0, highlightthickness=0); txt_scroll_y.config(command=txt.yview); txt_scroll_x.config(command=txt.xview); txt_scroll_y.pack(side="right", fill="y"); txt_scroll_x.pack(side="bottom", fill="x"); txt.pack(fill="both", expand=True); self.notebook.add(frame, text=name); return txt

    def setup_font_and_style(self):
        os_name = platform.system();
        try:
            fonts = tkfont.families(); font_found = False; font_prefs = ["Inter"]
            if os_name == "Windows": font_prefs.extend(["Segoe UI", "Arial"])
            elif os_name == "Darwin": font_prefs.extend(["San Francisco", "Helvetica Neue", "Helvetica", "Arial"])
            else: font_prefs.extend(["Helvetica", "Arial"])
            for font_name in font_prefs:
                 if font_name in fonts: self.default_font_name = font_name; font_found = True; break
            if not font_found: self.default_font_name = "TkDefaultFont"
        except: self.default_font_name = "TkDefaultFont"
        default_size = 10 if os_name != "Windows" else 9
        self.default_font = (self.default_font_name, default_size); self.default_font_bold = (self.default_font_name, default_size, "bold"); self.root.option_add("*Font", self.default_font)
        style = ttk.Style();
        try: style.theme_use("clam")
        except: pass
        BG="#2E2E2E"; INACTIVE_BG="#252526"; INACTIVE_FG="#A0A0A0"; ACCENT="#007ACC"; SELECT_BG="#3A3D41"; BORDER="#3E3E3E"
        style.configure(".", background=BG, foreground=self.FG, fieldbackground=INACTIVE_BG, troughcolor=INACTIVE_BG, borderwidth=0, highlightthickness=0, font=self.default_font)
        style.map(".", foreground=[('disabled', INACTIVE_FG), ('active', self.FG)], background=[('disabled', INACTIVE_BG), ('active', ACCENT)], fieldbackground=[('disabled', INACTIVE_BG)])
        style.configure("TFrame", background=BG); style.configure("TLabel", background=BG, foreground=self.FG, padding=(0, 2)); style.configure("TButton", padding=(8, 6), background=INACTIVE_BG, foreground=self.FG); style.map("TButton", background=[('active', SELECT_BG)])
        style.configure("Accent.TButton", padding=(8, 6), background=ACCENT, foreground="#FFFFFF"); style.map("Accent.TButton", background=[('active', "#005a9e")]); style.configure("TEntry", padding=5, bordercolor=BORDER, borderwidth=1, insertcolor=self.FG); style.map("TEntry", bordercolor=[('focus', ACCENT)], fieldbackground=[('focus', INACTIVE_BG)])
        style.configure("Treeview", rowheight=25, fieldbackground=INACTIVE_BG, background=INACTIVE_BG, foreground=self.FG); style.map("Treeview", background=[('selected', ACCENT)], foreground=[('selected', "#FFFFFF")]); style.configure("Treeview.Heading", font=self.default_font_bold, background=INACTIVE_BG, foreground=self.FG, padding=(8, 8)); style.map("Treeview.Heading", background=[('active', SELECT_BG)])
        style.configure("TNotebook", background=BG, borderwidth=0, padding=(0, 5)); style.configure("TNotebook.Tab", background=INACTIVE_BG, foreground=INACTIVE_FG, padding=(14, 7), font=(self.default_font_name, default_size)); style.map("TNotebook.Tab", background=[('selected', BG)], foreground=[('selected', self.FG)])
        style.configure("TProgressbar", troughcolor=INACTIVE_BG, background=ACCENT)

    def browse(self):
        p = filedialog.askopenfilename(filetypes=[("IPA files", "*.ipa"), ("All files", "*.*")])
        if p: self.path_var.set(p); self.clear_results(); self.status_var.set(f"Selected: {os.path.basename(p)}")

    def clear_results(self):
        if self.current_analyzer: self.current_analyzer.cleanup(); self.current_analyzer = None
        self.tree.delete(*self.tree.get_children());
        for i in self.file_tree.get_children(): self.file_tree.delete(i)
        self.summary_tab.config(state="normal"); self.info_tab.config(state="normal"); self.ent_tab.config(state="normal"); self.strings_tab.config(state="normal")
        self.summary_tab.delete("1.0", "end"); self.info_tab.delete("1.0", "end"); self.ent_tab.delete("1.0", "end"); self.strings_tab.delete("1.0", "end")
        self.summary_tab.config(state="disabled"); self.info_tab.config(state="disabled"); self.ent_tab.config(state="disabled"); self.strings_tab.config(state="disabled")
        self.score_label.config(text="Risk: N/A", foreground=self.FG); self.analyzer_details = {}; self.analyzer_findings = []; self.selected_file_path = ""; self.file_search_var.set(""); self.findings_search_var.set("")
        # self.warned_about_modifications = False # Keep warning status per session
        if self.progress_window and self.progress_window.winfo_exists(): self.progress_window.destroy(); self.progress_window = None; self.log_text_widget = None
        self.status_var.set("Ready")

    def _populate_file_tree_recursive(self, parent_node, tree_dict, current_path="", search_term=""):
        found_match = False; search_term = search_term.lower(); items = sorted(tree_dict.items()); folders = [(n, c) for n, c in items if isinstance(c, dict)]; files = [(n, c) for n, c in items if not isinstance(c, dict)]
        for name, content in folders + files:
            rel_path = f"{current_path}/{name}" if current_path else name; name_lower = name.lower()
            if isinstance(content, dict):
                child_node = self.file_tree.insert(parent_node, "end", text=name, open=False, values=(rel_path,), image=self.folder_icon)
                child_matched = self._populate_file_tree_recursive(child_node, content, rel_path, search_term)
                if child_matched: found_match = True
                elif search_term and search_term not in name_lower: self.file_tree.delete(child_node)
                if search_term and (search_term in name_lower or child_matched): self.file_tree.item(child_node, open=True); found_match = True
            else:
                if not search_term or search_term in name_lower: self.file_tree.insert(parent_node, "end", text=name, values=(rel_path,), image=self.file_icon); found_match = True
        return found_match
    
    def search_files(self, *args):
        if not self.analyzer_details: return
        for i in self.file_tree.get_children(): self.file_tree.delete(i)
        search_term = self.file_search_var.get(); self._populate_file_tree_recursive("", self.analyzer_details.get("file_tree", {}), search_term=search_term)

    def filter_findings(self, *args):
        search_term = self.findings_search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        if not self.analyzer_findings: return
        for cat, info_val in self.analyzer_findings:
            if not search_term or search_term in cat.lower() or search_term in str(info_val).lower():
                 self.tree.insert("", "end", values=(cat, info_val))

    def show_file_tree_menu(self, event):
        self.selected_file_path = ""; iid = self.file_tree.identify_row(event.y);
        if not iid: return; self.file_tree.focus(iid); self.file_tree.selection_set(iid); item = self.file_tree.item(iid)
        is_file_node = not self.file_tree.get_children(iid); rel_path = item["values"][0].replace("/", os.sep);
        if not self.analyzer_details.get("app_path"): return; full_path = os.path.join(self.analyzer_details["app_path"], rel_path)
        for i in range(self.file_tree_menu.index("end") + 1):
            try: self.file_tree_menu.entryconfig(i, state="disabled")
            except tk.TclError: pass
        if is_file_node and os.path.isfile(full_path):
            self.selected_file_path = full_path; self.file_tree_menu.entryconfig("Export Selected File", state="normal")
            ext = os.path.splitext(full_path)[1].lower(); text_exts = ('.plist', '.xml', '.txt', '.json', '.js', '.sh', '.py', '.rb', '.pl', '.command', '.strings', '.log'); img_exts = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.icns')
            if ext in text_exts or ext in img_exts: self.file_tree_menu.entryconfig("View File", state="normal")
            if ext in text_exts: self.file_tree_menu.entryconfig("Edit File", state="normal")
            self.file_tree_menu.entryconfig("View Strings", state="normal"); self.file_tree_menu.entryconfig("View as Hex", state="normal"); self.file_tree_menu.entryconfig("Get SHA256 Hash", state="normal"); self.file_tree_menu.entryconfig("Lookup Hash on VirusTotal", state="normal")
        self.file_tree_menu.post(event.x_root, event.y_root)

    def export_file_tree_selection(self):
        if not self.selected_file_path: return
        save_path = filedialog.asksaveasfilename(initialfile=os.path.basename(self.selected_file_path))
        if save_path:
            try: shutil.copy(self.selected_file_path, save_path); messagebox.showinfo("Export Successful", f"File saved to {save_path}")
            except Exception as e: messagebox.showerror("Export Failed", str(e))

    def view_file_tree_selection(self):
        if not self.selected_file_path: return
        path = self.selected_file_path; ext = os.path.splitext(path)[1].lower()
        text_exts = ('.plist', '.xml', '.txt', '.json', '.js', '.sh', '.py', '.rb', '.pl', '.command', '.strings', '.log'); img_exts = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.icns')
        if ext in text_exts: self.show_text_viewer(path, is_plist=ext in ('.plist', '.strings'))
        elif ext in img_exts: self.show_image_viewer(path)
        else: messagebox.showinfo("Cannot View", "This file type cannot be previewed. Please export it or use 'View as Hex'/'View Strings'.")

    def edit_file_tree_selection(self):
        if not self.selected_file_path: return
        if not self.warned_about_modifications:
            warn_msg = ("Warning: Modifying files inside an IPA will break its code signature.\n\nThe app will NOT install or run unless it is properly re-signed with a certificate.\n\nDo you want to continue editing anyway?");
            if messagebox.askyesno("Signature Warning", warn_msg, icon='warning'): self.warned_about_modifications = True
            else: return
        path = self.selected_file_path; ext = os.path.splitext(path)[1].lower(); text_exts = ('.plist', '.xml', '.txt', '.json', '.js', '.sh', '.py', '.rb', '.pl', '.command', '.strings', '.log')
        if ext in text_exts: self.show_text_editor(path)
        else: messagebox.showinfo("Cannot Edit", "Only text-based files can be edited.")
            
    def show_text_viewer(self, path, is_plist=False, content_override=None, title_prefix="Viewer"):
        win = tk.Toplevel(self.root); win.title(f"{title_prefix} - {os.path.basename(path)}"); win.geometry("700x500"); win.configure(bg="#2E2E2E")
        txt_frame = ttk.Frame(win, style="TFrame"); txt_frame.pack(fill="both", expand=True, padx=5, pady=(5,0))
        txt_scroll_y = ttk.Scrollbar(txt_frame, orient="vertical"); txt_scroll_x = ttk.Scrollbar(txt_frame, orient="horizontal"); txt = tk.Text(txt_frame, wrap="none", bg="#1E1E1E", fg="#D4D4D4", insertbackground="#D4D4D4", selectbackground="#3A3D41", font=("Courier", 10), yscrollcommand=txt_scroll_y.set, xscrollcommand=txt_scroll_x.set, padx=5, pady=5, bd=0, highlightthickness=0)
        txt_scroll_y.config(command=txt.yview); txt_scroll_x.config(command=txt.xview); txt_scroll_y.pack(side="right", fill="y"); txt_scroll_x.pack(side="bottom", fill="x"); txt.pack(fill="both", expand=True)
        content = ""; data = b""
        try:
            if content_override is not None: content = content_override
            else:
                with open(path, "rb") as f: data = f.read()
                if is_plist:
                    try: plist_data = plistlib.loads(data); content = json.dumps(plist_data, indent=2)
                    except Exception as plist_err: content = f"Error parsing as Plist:\n{plist_err}\n\n--- Raw Data ---\n{data.decode('utf-8', errors='replace')}"
                else: content = data.decode('utf-8', errors='replace')
        except Exception as e: content = f"Error reading file:\n\n{e}\n\n{traceback.format_exc()}"
        txt.insert("1.0", content); txt.config(state="disabled")
        def copy_to_clipboard(): self.root.clipboard_clear(); self.root.clipboard_append(txt.get("1.0", "end-1c")); messagebox.showinfo("Copied", "Contents copied to clipboard.", parent=win)
        copy_button = ttk.Button(win, text="Copy to Clipboard", command=copy_to_clipboard, style="TButton"); copy_button.pack(pady=5)

    def show_text_editor(self, path):
        win = tk.Toplevel(self.root); win.title(f"Editor - {os.path.basename(path)}"); win.geometry("700x500"); win.configure(bg="#2E2E2E")
        txt_frame = ttk.Frame(win, style="TFrame"); txt_frame.pack(fill="both", expand=True, padx=5, pady=(5,0))
        txt_scroll_y = ttk.Scrollbar(txt_frame, orient="vertical"); txt_scroll_x = ttk.Scrollbar(txt_frame, orient="horizontal"); txt = tk.Text(txt_frame, wrap="none", bg="#1E1E1E", fg="#D4D4D4", insertbackground="#D4D4D4", selectbackground="#3A3D41", font=("Courier", 10), undo=True, yscrollcommand=txt_scroll_y.set, xscrollcommand=txt_scroll_x.set, padx=5, pady=5, bd=0, highlightthickness=0)
        txt_scroll_y.config(command=txt.yview); txt_scroll_x.config(command=txt.xview); txt_scroll_y.pack(side="right", fill="y"); txt_scroll_x.pack(side="bottom", fill="x"); txt.pack(fill="both", expand=True)
        content = ""; encoding = 'utf-8'
        try:
            try:
                with open(path, "r", encoding=encoding, errors='strict') as f: content = f.read()
            except UnicodeDecodeError:
                encoding = 'latin-1'
                with open(path, "r", encoding=encoding, errors='replace') as f: content = f.read()
        except Exception as e: messagebox.showerror("Read Error", f"Could not read file {os.path.basename(path)}:\n{e}", parent=win); win.destroy(); return
        txt.insert("1.0", content)
        def save_changes():
            try:
                new_content = txt.get("1.0", "end-1c")
                with open(path, "w", encoding=encoding, errors='replace') as f: f.write(new_content)
                messagebox.showinfo("Saved", f"{os.path.basename(path)} saved successfully.", parent=win); win.destroy()
            except Exception as e: messagebox.showerror("Save Error", f"Could not save file:\n{e}", parent=win)
        save_button = ttk.Button(win, text="Save Changes", command=save_changes, style="Accent.TButton"); save_button.pack(pady=5)

    def show_image_viewer(self, path):
        win = tk.Toplevel(self.root); win.title(f"Image - {os.path.basename(path)}"); win.configure(bg="#2E2E2E")
        try:
            img = Image.open(path); photo = ImageTk.PhotoImage(img)
            label = ttk.Label(win, image=photo, style="TLabel"); label.image = photo; label.pack(padx=10, pady=10)
            win.geometry(f"{photo.width()+20}x{photo.height()+20}")
        except Exception as e: win.destroy(); messagebox.showerror("Image Error", f"Could not load image: {e}\n\n{traceback.format_exc()}")
            
    def _get_file_strings(self, data):
        min_len = 4; strings = ""; current = ""; printable_chars = set(bytes(string.printable, 'ascii'))
        for byte in data:
            if byte in printable_chars: current += chr(byte)
            else:
                if len(current) >= min_len: strings += current + "\n"
                current = ""
        if len(current) >= min_len: strings += current
        return strings
        
    def _format_hex(self, data):
        out = ""; ascii_part = ""; hex_part = ""
        for i in range(0, len(data), 16): chunk = data[i:i+16]; offset = f"{i:08x}"; hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(16 * 3 - 1); ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk); out += f"{offset} | {hex_part} | {ascii_part}\n"
        return out
        
    def view_file_strings(self):
        if not self.selected_file_path: return
        try:
            with open(self.selected_file_path, "rb") as f: data = f.read()
            strings = self._get_file_strings(data);
            if not strings: strings = "--- No printable strings found ---"
            self.show_text_viewer(self.selected_file_path, content_override=strings, title_prefix="Strings")
        except Exception as e: messagebox.showerror("Error Reading Strings", str(e))

    def view_file_hex(self):
        if not self.selected_file_path: return
        try:
            with open(self.selected_file_path, "rb") as f: data = f.read(1024 * 1024)
            hex_content = self._format_hex(data)
            if len(data) == 1024 * 1024: hex_content += f"\n--- Truncated at 1MB ---"
            self.show_text_viewer(self.selected_file_path, content_override=hex_content, title_prefix="Hex")
        except Exception as e: messagebox.showerror("Error Reading File", str(e))
            
    def get_file_hash(self):
        if not self.selected_file_path: return
        try:
            h = sha256_of_file(self.selected_file_path)
            if h == "Error Hashing": raise ValueError("Could not hash file.")
            content = f"File: {os.path.basename(self.selected_file_path)}\n\nSHA256: {h}"
            self.show_text_viewer(self.selected_file_path, content_override=content, title_prefix="SHA256 Hash")
        except Exception as e: messagebox.showerror("Error Hashing File", str(e))

    def lookup_hash_vt(self):
        if not self.selected_file_path: return
        try:
            file_hash = sha256_of_file(self.selected_file_path)
            if file_hash == "Error Hashing": raise ValueError("Could not get file hash.")
            url = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
            webbrowser.open(url)
            self.status_var.set(f"Opened VirusTotal for {os.path.basename(self.selected_file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not look up hash:\n{e}")
            self.status_var.set("Error looking up hash.")
            
    def show_findings_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid: return
        self.tree.focus(iid)
        self.tree.selection_set(iid)
        self.findings_tree_menu.post(event.x_root, event.y_root)

    def copy_finding_value(self):
        try:
            selected_item = self.tree.selection()[0]
            value = self.tree.item(selected_item, "values")[1]
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
        except Exception as e:
            messagebox.showerror("Error", f"Could not copy value: {e}", parent=self.root)

    def _insert_text(self, text_widget, content):
        text_widget.config(state="normal")
        text_widget.delete("1.0", "end")
        text_widget.insert("1.0", content)
        text_widget.config(state="disabled")

    def _show_progress_dialog(self):
        if self.progress_window and self.progress_window.winfo_exists(): self.progress_window.destroy()
        self.progress_window = tk.Toplevel(self.root); self.progress_window.title("Analyzing IPA...");
        prog_win_width = 600; prog_win_height = 400
        self.progress_window.geometry(f"{prog_win_width}x{prog_win_height}")
        self.progress_window.configure(bg="#2E2E2E"); self.progress_window.transient(self.root); self.progress_window.grab_set(); self.progress_window.resizable(False, False)
        self.root.update_idletasks()
        main_win_x = self.root.winfo_x(); main_win_y = self.root.winfo_y(); main_win_width = self.root.winfo_width(); main_win_height = self.root.winfo_height()
        center_x = main_win_x + (main_win_width // 2) - (prog_win_width // 2); center_y = main_win_y + (main_win_height // 2) - (prog_win_height // 2)
        self.progress_window.geometry(f"+{center_x}+{center_y}")
        ttk.Label(self.progress_window, text="Analysis in progress...", font=self.default_font_bold).pack(pady=(10, 5))
        pb = ttk.Progressbar(self.progress_window, mode='indeterminate', style="TProgressbar"); pb.pack(fill="x", padx=10, pady=5); pb.start(10)
        log_frame = ttk.Frame(self.progress_window, style="TFrame"); log_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical"); self.log_text_widget = tk.Text(log_frame, wrap="word", bg="#1E1E1E", fg="#D4D4D4", font=("Courier", 9), yscrollcommand=log_scroll.set, padx=5, pady=5, bd=0, highlightthickness=0, state="disabled"); log_scroll.config(command=self.log_text_widget.yview); log_scroll.pack(side="right", fill="y"); self.log_text_widget.pack(fill="both", expand=True)
        self.progress_window.protocol("WM_DELETE_WINDOW", lambda: None)

    def _update_log(self, message):
        if self.log_text_widget and self.log_text_widget.winfo_exists():
            self.log_text_widget.config(state="normal")
            self.log_text_widget.insert("end", message)
            self.log_text_widget.see("end")
            self.log_text_widget.config(state="disabled")

    def _run_analysis_thread(self, ipa_path):
        analyzer = None; analysis_error = None
        try:
            log_callback = lambda msg: self.root.after(0, self._update_log, msg)
            analyzer = Analyzer(ipa_path, log_callback=log_callback); analyzer.run()
        except Exception as e:
            analysis_error = e; traceback.print_exc()
            log_callback(f"FATAL ERROR during analysis thread: {e}\n{traceback.format_exc()}")
        finally:
            self.root.after(0, self._analysis_complete, analyzer, analysis_error)

    def _analysis_complete(self, analyzer, error):
        if self.progress_window and self.progress_window.winfo_exists():
            self.progress_window.destroy(); self.progress_window = None; self.log_text_widget = None
        self.analyze_button.config(state="normal")
        if error: messagebox.showerror("Analysis Failed", f"An unexpected error occurred during analysis:\n{error}");
        if analyzer: self.current_analyzer = analyzer
        else: messagebox.showerror("Analysis Error", "Analyzer object not found after thread completion."); return
        if error: return

        self.analyzer_details = analyzer.details; self.analyzer_findings = analyzer.findings
        self.filter_findings() # Apply initial filter (which is none)
        info = analyzer.details.get("info", {}); ent = analyzer.details.get("entitlements", {})
        summary_text = (f"App Name: {info.get('CFBundleName', 'N/A')}\nBundle ID: {info.get('CFBundleIdentifier', 'N/A')}\nVersion: {info.get('CFBundleShortVersionString', 'N/A')}\n\nRisk Score: {analyzer.score}\nScanned: {analyzer.details.get('scanned_at', 'N/A')}\n\n--- Key Details ---\n"
                        f"Entitlements Source: {analyzer.details.get('entitlements_source', 'N/A')}\nTotal Files in .app: {len(analyzer.details.get('files', []))}\nDetected Injected Dylibs: {len(analyzer.details.get('injected_dylibs', []))}\nKnown Tracking Libs: {len(set(analyzer.details.get('tracking_libs', [])))}\n"
                        f"Suspicious Imports: {len(set(analyzer.details.get('suspicious_imports', [])))}\nJailbreak Strings: {len(set(analyzer.details.get('jailbreak_strings', [])))}\nFound URLs: {len(analyzer.details.get('extracted_urls', []))}\nFound IPs: {len(set(analyzer.details.get('extracted_ips', [])))}\n"
                        f"Found DDNS Domains: {len(set(analyzer.details.get('suspicious_ddns', [])))}\nHardcoded AWS Keys: {len(set(analyzer.details.get('hardcoded_aws_keys', [])))}\n")
        self._insert_text(self.summary_tab, summary_text)
        for i in self.file_tree.get_children(): self.file_tree.delete(i)
        self._populate_file_tree_recursive("", analyzer.details.get("file_tree", {}), search_term="")
        self._insert_text(self.info_tab, json.dumps(info, indent=2)); self._insert_text(self.ent_tab, json.dumps(ent, indent=2))
        strings_text = "--- SUSPICIOUS IMPORTS / FUNCTIONS ---\n" + "\n".join(sorted(list(set(analyzer.details.get("suspicious_imports", ["None"]))))) + \
                       "\n\n--- JAILBREAK STRINGS / PATHS ---\n" + "\n".join(sorted(list(set(analyzer.details.get("jailbreak_strings", ["None"]))))) + \
                       "\n\n--- KNOWN TRACKING LIBRARIES ---\n" + "\n".join(sorted(list(set(analyzer.details.get("tracking_libs", ["None"]))))) + \
                       "\n\n--- SUSPICIOUS DDNS (C2?) ---\n" + "\n".join(sorted(list(set(analyzer.details.get("suspicious_ddns", ["None"]))))) + \
                       "\n\n--- EXTRACTED URLs ---\n" + "\n".join(analyzer.details.get("extracted_urls", ["None"])) + \
                       "\n\n--- EXTRACTED IPs ---\n" + "\n".join(sorted(list(set(analyzer.details.get("extracted_ips", ["None"]))))) + \
                       "\n\n--- WEAK HASHES (MD5/SHA1) ---\n" + "\n".join(sorted(list(set(analyzer.details.get("weak_hashes", ["None"]))))) + \
                       "\n\n--- ENCRYPTION LIBRARIES ---\n" + "\n".join(sorted(list(set(analyzer.details.get("crypto_libs", ["None"]))))) + \
                       "\n\n--- POTENTIAL HARDCODED AWS KEYS ---\n" + "\n".join(sorted(list(set(analyzer.details.get("hardcoded_aws_keys", ["None"]))))) + \
                       "\n\n--- POTENTIAL HARDCODED Google API KEYS ---\n" + "\n".join(sorted(list(set(analyzer.details.get("hardcoded_google_keys", ["None"]))))) + \
                       "\n\n--- POTENTIAL HARDCODED Facebook IDs ---\n" + "\n".join(sorted(list(set(analyzer.details.get("hardcoded_fb_ids", ["None"]))))) + \
                       "\n\n--- POTENTIAL HARDCODED GENERIC SECRETS ---\n" + "\n".join(sorted(list(set(analyzer.details.get("hardcoded_generic_secrets", ["None"])))))
        self._insert_text(self.strings_tab, strings_text)
        label, color = self.risk_label_color(analyzer.score); self.score_label.config(text=f"Risk: {label} ({analyzer.score})", foreground=color)
        self.status_var.set(f"Analysis complete: {os.path.basename(self.path_var.get())}")

    def analyze(self):
        p = self.path_var.get().strip();
        if not p or not os.path.exists(p): messagebox.showerror("Error", "Select a valid IPA file"); return
        self.clear_results(); self.root.update_idletasks()
        self._show_progress_dialog(); self.analyze_button.config(state="disabled")
        self.status_var.set("Analyzing...")
        analysis_thread = threading.Thread(target=self._run_analysis_thread, args=(p,), daemon=True); analysis_thread.start()

    def risk_label_color(self, score):
        if score <= 5: return ("Low", "#4CAF50")
        if score <= 15: return ("Moderate", "#FFC107")
        if score <= 30: return ("High", "#FF9800")
        return ("Critical", "#F44336")

    def save_findings(self):
        if not self.analyzer_findings: messagebox.showinfo("Info", "No findings to save. Run an analysis first."); return
        p = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")]);
        if not p: return
        try:
            with open(p, "w", encoding="utf-8") as f: f.write(f"AppShield IPA Analysis Report\nFile: {self.path_var.get()}\nRisk Score: {self.analyzer_details.get('risk_score', 'N/A')}\nScanned: {self.analyzer_details.get('scanned_at', 'N/A')}\n" + "-" * 30 + "\n\n");
            for cat, info_val in self.analyzer_findings: f.write(f"[{cat}]\t{info_val}\n")
            messagebox.showinfo("Saved", f"Findings saved to {p}")
        except Exception as e: messagebox.showerror("Save Failed", f"Could not save file: {e}")

    def export_json(self):
        if not self.analyzer_details: messagebox.showinfo("Info", "No details to export. Run an analysis first."); return
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")]);
        if not p: return
        details_copy = self.analyzer_details.copy();
        for key, value in details_copy.items():
            if isinstance(value, set): details_copy[key] = sorted(list(value))
        full_report = {"summary": {"file": self.path_var.get(), "risk_score": details_copy.get('risk_score'), "scanned_at": details_copy.get('scanned_at')}, "findings": [{"category": f[0], "detail": f[1]} for f in self.analyzer_findings], "details": details_copy }
        try:
            with open(p, "w", encoding="utf-8") as f: json.dump(full_report, f, indent=2)
            messagebox.showinfo("Exported", f"Full analysis report exported to {p}")
        except Exception as e: messagebox.showerror("Export Failed", f"Could not export JSON: {e}")

    def repackage_ipa(self):
        if not self.current_analyzer or not self.analyzer_details.get("app_path"): messagebox.showerror("Error", "Please analyze an IPA before attempting to repackage."); return
        warn_msg = ("Warning: Repackaging this IPA will result in an UNSIGNED application.\n\nIt will NOT install on a standard iOS device unless it is properly re-signed using official Apple tools (like Xcode on macOS).\n\nDo you want to proceed and create an unsigned IPA?")
        if not messagebox.askyesno("Unsigned IPA Warning", warn_msg, icon='warning'): return
        save_path = filedialog.asksaveasfilename(defaultextension=".ipa", initialfile=f"modified_{os.path.basename(self.path_var.get())}", filetypes=[("IPA files", "*.ipa")])
        if not save_path: return
        payload_dir = os.path.join(self.current_analyzer.tmpdir, "Payload")
        self.status_var.set("Repackaging unsigned IPA...")
        self.root.update_idletasks()
        try:
            with zipfile.ZipFile(save_path, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                for root, dirs, files in os.walk(payload_dir):
                    arc_root = os.path.relpath(root, self.current_analyzer.tmpdir).replace(os.sep, '/')
                    for file in files: full_path = os.path.join(root, file); arcname = f"{arc_root}/{file}"; new_zip.write(full_path, arcname)
                for item in os.listdir(self.current_analyzer.tmpdir):
                     item_path = os.path.join(self.current_analyzer.tmpdir, item)
                     if item != "Payload" and os.path.isfile(item_path): new_zip.write(item_path, item)
            messagebox.showinfo("Repackage Successful", f"Unsigned IPA saved to:\n{save_path}")
            self.status_var.set("Unsigned repackage complete.")
        except Exception as e: messagebox.showerror("Repackage Failed", f"Could not create IPA file:\n{e}\n\n{traceback.format_exc()}"); self.status_var.set("Repackage failed.")

    def repackage_signed_ipa(self):
        messagebox.showinfo("Not Implemented", "Signed repackaging requires external tools (like zsign) and is not implemented in this version.")
        self.status_var.set("Signed repackage requires external tools.")

    def open_temp_folder(self):
        if self.current_analyzer and hasattr(self.current_analyzer, 'tmpdir') and os.path.exists(self.current_analyzer.tmpdir):
            try:
                if platform.system() == "Windows": os.startfile(self.current_analyzer.tmpdir)
                elif platform.system() == "Darwin": subprocess.Popen(["open", self.current_analyzer.tmpdir])
                else: subprocess.Popen(["xdg-open", self.current_analyzer.tmpdir])
                self.status_var.set(f"Opened temp folder: {self.current_analyzer.tmpdir}")
            except Exception as e: messagebox.showerror("Error", f"Could not open temporary folder:\n{e}"); self.status_var.set("Error opening temp folder.")
        else: messagebox.showinfo("Info", "No analysis is currently active (no temporary folder to open)."); self.status_var.set("No temp folder to open.")

    def expand_collapse_all(self, treeview, expand=True):
         if not treeview.get_children(): return
         for item in treeview.get_children():
             treeview.item(item, open=expand)
             if treeview == self.file_tree: # Recursive only needed for file tree
                 if expand: self._expand_all_children(treeview, item)
                 else: self._collapse_all_children(treeview, item) # Ensure children collapse

    def _expand_all_children(self, treeview, item):
         if treeview.get_children(item):
             treeview.item(item, open=True)
             for child in treeview.get_children(item): self._expand_all_children(treeview, child)

    def _collapse_all_children(self, treeview, item):
         if treeview.get_children(item):
             treeview.item(item, open=False)
             for child in treeview.get_children(item): self._collapse_all_children(treeview, child)

    def generate_summary_report(self):
        if not self.analyzer_findings: messagebox.showinfo("Info", "No findings to generate a report from."); return
        info = self.analyzer_details.get("info", {})
        report_content = f"AppShield Summary Report\n{'='*30}\n\n"
        report_content += f"File Analyzed: {os.path.basename(self.path_var.get())}\n"
        report_content += f"App Name: {info.get('CFBundleName', 'N/A')}\n"
        report_content += f"Bundle ID: {info.get('CFBundleIdentifier', 'N/A')}\n"
        report_content += f"Version: {info.get('CFBundleShortVersionString', 'N/A')}\n"
        report_content += f"Risk Score: {self.analyzer_details.get('risk_score', 'N/A')}\n"
        report_content += f"Scanned At: {self.analyzer_details.get('scanned_at', 'N/A')}\n\n"
        report_content += f"Key Findings:\n{'-'*20}\n"
        priority_cats = ["Error", "Injection", "Tampering", "Security", "Suspicious", "Anti-Debug", "Network", "Privacy", "Entitlement", "Keychain", "Binary Size", "Binary", "Sandbox", "Files", "Permission", "Provision", "Info", "App"]
        findings_by_cat = {}
        for cat, val in self.analyzer_findings: findings_by_cat.setdefault(cat, []).append(val)
        for cat in priority_cats:
            if cat in findings_by_cat:
                report_content += f"\n[{cat}]\n"
                for val in findings_by_cat[cat][:5]: report_content += f"- {val}\n"
                if len(findings_by_cat[cat]) > 5: report_content += "- ... (and more)\n"
        self.show_text_viewer("SummaryReport.txt", content_override=report_content, title_prefix="Report")

    def show_entitlement_explorer(self):
        descriptions = {
             "App Sandbox": {"com.apple.security.app-sandbox": "Enables the App Sandbox. Should generally be TRUE."},
             "Debugging": {"get-task-allow": "Allows debuggers/other processes to attach. HIGH RISK if TRUE in production."},
             "Code Signing": {
                 "com.apple.security.cs.allow-jit": "Allows Just-In-Time compilation (e.g., for JavaScript). Can be abused.",
                 "com.apple.security.cs.allow-unsigned-executable-memory": "Allows writing+executing unsigned code in memory. HIGH RISK.",
                 "com.apple.security.cs.disable-library-validation": "Disables checks ensuring loaded libraries are signed by Apple/same team. HIGH RISK.",
                 "com.apple.security.cs.disable-executable-page-protection": "Disables Data Execution Prevention (DEP/NX). HIGH RISK.",
                 "com.apple.security.cs.debugger": "Allows the app to act as a debugger (requires special certificate)."
             },
             "Data Access": {
                 "com.apple.developer.contacts.notes": "Allows accessing the notes field in contacts.",
                 "com.apple.developer.healthkit": "Allows accessing HealthKit data.",
                 "com.apple.developer.healthkit.access": "(Deprecated) Older HealthKit access.",
                 "com.apple.developer.photos.library.add": "Allows adding assets to the photo library.",
                 "com.apple.security.personal-information.location-always": "(Deprecated) Older location access.",
                 "com.apple.security.personal-information.photos-library": "(Deprecated) Older photos access."
             },
             "Networking": {
                 "com.apple.developer.networking.networkextension": "Allows creating system-level network extensions (VPN, content filters).",
                 "com.apple.developer.networking.vpn.configuration": "Allows managing VPN configurations.",
                 "com.apple.security.network.client": "Allows making outgoing network connections.",
                 "com.apple.security.network.server": "Allows listening for incoming network connections."
             },
             "App Services": {
                 "aps-environment": "Configures Push Notifications ('development' or 'production').",
                 "com.apple.developer.associated-domains": "Used for Universal Links, Handoff, Shared Web Credentials.",
                 "com.apple.developer.icloud-container-identifiers": "Enables iCloud Key-Value or CloudKit storage.",
                 "com.apple.developer.icloud-services": "Specifies iCloud services used.",
                 "com.apple.developer.in-app-payments": "Enables Apple Pay.",
                 "com.apple.developer.siri": "Allows integration with SiriKit.",
                 "com.apple.developer.pass-type-identifiers": "Defines Wallet pass types the app can interact with."
             },
             "Hardware/Device": {
                 "com.apple.developer.devicecheck.appattest-environment": "Enables DeviceCheck App Attest service.",
                 "com.apple.developer.nfc.readersession.formats": "Allows reading NFC tags.",
                 "com.apple.developer.homekit": "Allows accessing HomeKit devices."
             },
             "System/Private (Suspicious/High Risk)": {
                 "com.apple.private.security.no-container": "Disables containerization (rare, potentially dangerous).",
                 "com.apple.private.skip-library-validation": "Similar to cs.disable-library-validation. HIGH RISK.",
                 "platform-application": "Indicates a system-level application.",
                 "com.apple.developer.kernel-extension": "Allows loading kernel extensions. Extremely rare & restricted.",
                 "com.apple.private.*": "Any entitlement starting with this prefix is private and potentially risky."
             },
             "Other Common": {
                "application-identifier": "App ID including Team ID prefix.",
                "keychain-access-groups": "Defines keychain items accessible. Wildcards (*) can be risky.",
                "com.apple.developer.team-identifier": "The developer Team ID.",
                "beta-reports-active": "Enables TestFlight crash reporting."
             }
        }
        content = "Common iOS Entitlements & Risks:\n" + "="*30 + "\n\n"
        for category, ents in descriptions.items():
            content += f"--- {category} ---\n"
            for key, desc in sorted(ents.items()):
                 content += f"'{key}':\n- {desc}\n\n"
        self.show_text_viewer("EntitlementExplorer.txt", content_override=content, title_prefix="Entitlements")

    def toggle_always_warn(self):
        self.warned_about_modifications = not self.warned_about_modifications
        status = "OFF" if self.warned_about_modifications else "ON"
        messagebox.showinfo("Settings", f"Signature modification warning is now {status}.")

    def reset_edit_warning(self): # Renamed for clarity
        self.warned_about_modifications = False
        messagebox.showinfo("Settings", "Signature warning will now show again on the next file edit.")

    def lookup_hash_vt(self):
        if not self.selected_file_path: return
        try:
            file_hash = sha256_of_file(self.selected_file_path)
            if file_hash == "Error Hashing": raise ValueError("Could not get file hash.")
            url = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
            webbrowser.open(url)
            self.status_var.set(f"Opened VirusTotal for {os.path.basename(self.selected_file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not look up hash:\n{e}")
            self.status_var.set("Error looking up hash.")


    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    AppUI().run()
