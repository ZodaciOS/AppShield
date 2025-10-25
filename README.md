# AppShield
Python script that analyzes an .ipa file and checks for 'malware'

**I CANNOT STRESS THIS ENOUGH! DO NOT RELY ON THIS TOOL! YOU WILL RECEIVE FALSE POSITIVES**

This tool is still in development and I am trying to update the tool more and more. Please, if you encounter any errors or issues, open a issue and explain in detail.

Don't report false positives. I know, you get flagged easily.

# Installation

Ensure Python is installed (scroll down for [Required Dependencies](#dependencies-required))
Tap on "main.py" in this github repo.

Tap the Download icon. Hovering your mouse over it should say "Download Raw File".

Then, tap open file.

# Features

- Reads app entitlements and detects debuggable applications (`get-task-allow`)
- Flags keychain access groups
- Identifies private Apple entitlements
- Flags root-level entitlements (practically useless)
- Detect entitlements for VPN & network access
- Detects entitlements that may allow sandbox escaping or abuse

# Binary & File Analysis

- Detects Mach-O binaries in a .ipa
- Computes SHA-256 encrypted hashes of main binaries for verification or duplication detection
- Detects large binaries
- Flags executables, scripts or suspicious binaries
- Detects scripts or binaries that may execute arbitary code

# File Explorer

- View .plist files
- Built in hex-viewer
- File exporter
- Get SHA256 of a file

**And a lot of other small features I won't cover.**

# Risk Scoring

- Colour-coded for low, moderate & high-risk and a number

# Dependencies Required

AppShield requires Pillow in order to view image files. If you aren't planning on viewing images, it is not required.

`pip install pillow` - Run in Terminal/Command Prompt

# To-dos

- Port to a Swift app
- Add ipa signing with ZSign backend
- Improve detection (as .dylib's are flagged)
- Add more flags


# The Rarity of iOS Viruses

One thing you should understand about iOS is that it is extremely difficult to obtain a persistent malware on your device.

By malware, something that can harm your device or 'brick' it. It is possible, but requires running multiple exploits. Most of these exploits exist on older iOS versions ( < iOS 16.6.1 ). 

This doesn't mean disclosed exploits exist on iOS versions above. Although the chances of finding one in the wild is rare, you should still be careful.

Now, talking about some of the features, entitlement checking is useful in some cases. This is only useful if:

- AMFI/Coretrust Bypass. Arbitary entitlements are permitted if bypassed.
- TrollStore Users. Again, arbitary entitlements are permitted (except for 3).
- Users that are jailbroken.

**Do not trust this tool solely.** It was not created for professional virus detection. It was only made as a basic app analysis.

# Entitlement Limitations

Even if we flag an entitlement, it may not even matter. iOS will verify the app entitlements ensuring it matches with the provisioning profile. 

The type of certificate depends on the entitlement. With the 3 types of certificates, **App Store, Developer & Enterprise**, enterprise has the least entitlement support. 

If you are signing with a enterprise certificate, VPN's and other select entitlements **will not work.**

This python script is decent for ipa analysis, but you may recieve false positives, especially on TrollStore applications.

