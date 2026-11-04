#!/usr/bin/env python3
"""Regenerate corpus/benign.csv.

Part 1 (B001-B030): one concrete instance of each row in corpus/benign_fp_generators.csv
(the provided FP-generator table), keeping its bypass_risk. Placeholders like <ver> are
filled with realistic values.

Part 2: expansion from the install docs of popular tools and ordinary dev / SRE / IT
work. Each row records the context it would realistically arrive in:
  origin  browser_vendor_docs | browser_internal | browser_unknown | application:<name> | unknown
  target  terminal:<shell> | run_dialog | unknown
"Copied from a blog / StackOverflow / GitHub README" is browser_unknown on purpose:
github.com hosts attacker content too, so it is never classified as vendor docs.

Add your own shell history with scripts/import_history.py (stays local).
"""
import csv
import os

V, I, U = "browser_vendor_docs", "browser_internal", "browser_unknown"
TERM, VSC = "application:gnome-terminal", "application:code"
BASH, ZSH, PS, CMD = "terminal:bash", "terminal:zsh", "terminal:powershell", "terminal:cmd"

JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
PEM = """-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD
VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX
-----END CERTIFICATE-----"""
SSHKEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDcH6a6Nn0wQb0sQWlFz3kJcF5o2y9Xx0Gk2p8fJ9rKUQAAAJgnB0qLJwdK
-----END OPENSSH PRIVATE KEY-----"""

# (category, platform, text, origin, target, role, bypass_risk, source_row, notes)
PART1 = [
    ("Pipe-to-shell installer", "linux", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh", V, BASH, "engineering", "HIGH", 1, "rustup.rs"),
    ("Pipe-to-shell installer", "macos", '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"', V, ZSH, "engineering", "HIGH", 2, "brew.sh"),
    ("Pipe-to-shell installer", "linux", "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash", U, BASH, "engineering", "HIGH", 3, "nvm README on github.com: unknown origin by policy"),
    ("Pipe-to-shell installer", "linux", "curl -fsSL https://get.docker.com | sh", V, BASH, "engineering", "HIGH", 4, "docs.docker.com"),
    ("Pipe-to-shell installer", "linux", "curl -fsSL https://deno.land/install.sh | sh", V, BASH, "engineering", "HIGH", 5, "deno.land"),
    ("Pipe-to-shell installer", "linux", "curl -sSL https://install.python-poetry.org | python3 -", V, BASH, "engineering", "HIGH", 6, "python-poetry.org"),
    ("Package manager bootstrap", "windows", "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))", V, PS, "admin", "HIGH", 7, "chocolatey.org: the single worst FP source"),
    ("Remote script by design", "windows", "iex (New-Object Net.WebClient).DownloadString('https://tools.corp.example/runbooks/reset-spooler.ps1')", I, PS, "admin", "HIGH", 8, "internal runbook"),
    ("Package manager bootstrap", "windows", "winget install --id Git.Git -e --source winget", V, PS, "engineering", "LOW", 9, ""),
    ("Encoded secret", "any", JWT, U, "unknown", "engineering", "LOW", 10, "jwt.io sample"),
    ("Encoded secret", "any", PEM, U, "unknown", "engineering", "LOW", 11, ""),
    ("Encoded secret", "any", "DATABASE_URL=postgres://app:Xk29fLq0pZ@db.internal:5432/app\nSTRIPE_SECRET_KEY=sk_test_51HyQ2bKj8sLmN0pQrStUvWxYz0123456789abcdef\nREDIS_URL=redis://cache:6379/0", VSC, "unknown", "engineering", "LOW", 12, ".env contents"),
    ("Encoded secret", "any", "3f786850e387550fdab836ed7e6dc881de23001b", TERM, "unknown", "engineering", "LOW", 13, "commit SHA"),
    ("Admin PowerShell", "windows", "Connect-ExchangeOnline -UserPrincipalName admin@contoso.com; Get-Mailbox -ResultSize Unlimited | Where-Object {$_.RecipientTypeDetails -eq 'SharedMailbox'} | Select-Object DisplayName,PrimarySmtpAddress | Export-Csv shared.csv -NoTypeInformation", I, PS, "admin", "LOW", 14, ""),
    ("Temp path write", "linux", 'tmp=$(mktemp -d) && tar -xzf release.tar.gz -C "$tmp" && cp "$tmp"/bin/* ~/.local/bin/', TERM, BASH, "engineering", "LOW", 15, ""),
    ("LOLBin", "windows", "certutil -hashfile .\\Downloads\\ubuntu-24.04-desktop-amd64.iso SHA256", U, PS, "engineering", "LOW", 16, ""),
    ("LOLBin", "windows", "rundll32.exe C:\\Windows\\System32\\shell32.dll,Control_RunDLL desk.cpl", U, "run_dialog", "standard", "LOW", 17, "System32 DLL export"),
    ("Developer fetch", "any", "curl -s -H 'Accept: application/json' https://api.github.com/repos/rust-lang/rust/releases/latest | jq -r .tag_name", U, BASH, "engineering", "LOW", 18, ""),
    ("Developer fetch", "any", "git clone https://github.com/BurntSushi/ripgrep && cd ripgrep && cargo build --release", U, BASH, "engineering", "LOW", 19, ""),
    ("Password manager paste", "any", "Tr0ub4dor&3-xK9#mQ2$vL7!pZ", "application:keepassxc", "unknown", "standard", "LOW", 20, "never logged by the daemon"),
    ("Minified or generated code", "any", "!function(e,t){\"object\"==typeof exports&&\"undefined\"!=typeof module?module.exports=t():\"function\"==typeof define&&define.amd?define(t):(e=e||self).dayjs=t()}(this,function(){\"use strict\";var e=1e3,t=6e4,n=36e5", VSC, "unknown", "engineering", "LOW", 21, ""),
    ("Encoded secret", "any", "kubectl get secret db-credentials -n prod -o jsonpath='{.data.password}' | base64 -d", I, BASH, "engineering", "MEDIUM", 22, ""),
    ("Admin PowerShell", "windows", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\fs01\\deploy$\\scripts\\Install-Agent.ps1", I, PS, "admin", "MEDIUM", 23, "SCCM/Intune style"),
    ("Admin PowerShell", "windows", "Invoke-WebRequest -Uri https://artifacts.corp.example/agent/2.4.1/agent.zip -OutFile C:\\Install\\agent.zip", I, PS, "admin", "MEDIUM", 24, ""),
    ("Temp path write", "linux", "mkdir -p /tmp/build && cmake -S . -B /tmp/build -DCMAKE_BUILD_TYPE=Release && cmake --build /tmp/build -j8", TERM, BASH, "engineering", "MEDIUM", 25, ""),
    ("LOLBin", "windows", "certutil -decode .\\cert.b64 .\\cert.cer", I, PS, "admin", "MEDIUM", 26, ""),
    ("LOLBin", "windows", "msiexec /i \\\\fs01\\deploy$\\7z2408-x64.msi /qn /norestart", I, CMD, "admin", "MEDIUM", 27, ""),
    ("LOLBin", "windows", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", I, CMD, "admin", "MEDIUM", 28, "query, not write"),
    ("LOLBin", "windows", "Expand-Archive -Path .\\build\\artifacts.zip -DestinationPath .\\dist -Force", VSC, PS, "engineering", "MEDIUM", 29, ""),
    ("Long one-liner", "any", "docker run --rm -it --name dev -v \"$PWD\":/work -w /work -e RUST_LOG=debug -e CARGO_HOME=/work/.cargo -p 8080:8080 --network host --cap-add SYS_PTRACE --security-opt seccomp=unconfined rust:1.80 bash -lc 'cargo build && cargo test'", TERM, BASH, "engineering", "N/A", 30, ""),
]

# Install docs: (platform, text, shell)
INSTALL = [
    ("linux", "curl -fsSL https://bun.sh/install | bash", BASH),
    ("linux", "curl -LsSf https://astral.sh/uv/install.sh | sh", BASH),
    ("windows", 'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"', PS),
    ("linux", "curl -sS https://starship.rs/install.sh | sh", BASH),
    ("linux", "curl -fsSL https://tailscale.com/install.sh | sh", BASH),
    ("linux", "curl -fsSL https://ollama.com/install.sh | sh", BASH),
    ("linux", "curl -sfL https://get.k3s.io | sh -", BASH),
    ("linux", 'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"', ZSH),
    ("linux", "curl https://sdk.cloud.google.com | bash", BASH),
    ("linux", "curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 && chmod 700 get_helm.sh && ./get_helm.sh", BASH),
    ("linux", 'curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"', BASH),
    ("linux", "sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl", BASH),
    ("linux", "curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -", BASH),
    ("linux", "sudo apt-get install -y nodejs", BASH),
    ("linux", "curl -fsSL https://get.pnpm.io/install.sh | sh -", BASH),
    ("windows", "Invoke-WebRequest https://get.pnpm.io/install.ps1 -UseBasicParsing | Invoke-Expression", PS),
    ("windows", "irm https://get.scoop.sh | iex", PS),
    ("windows", "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser", PS),
    ("windows", 'powershell -c "irm bun.sh/install.ps1 | iex"', PS),
    ("windows", "winget install --id Microsoft.PowerShell --source winget", PS),
    ("windows", "winget install -e --id Python.Python.3.12", PS),
    ("windows", "Install-Module -Name Az -Repository PSGallery -Force", PS),
    ("windows", "Install-Module ExchangeOnlineManagement -Scope CurrentUser", PS),
    ("windows", "wsl --install -d Ubuntu-24.04", PS),
    ("linux", "sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg", BASH),
    ("linux", "sudo install -m 0755 -d /etc/apt/keyrings && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg", BASH),
    ("linux", 'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null', BASH),
    ("linux", "sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin", BASH),
    ("linux", "sudo usermod -aG docker $USER && newgrp docker", BASH),
    ("linux", "wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg", BASH),
    ("linux", "curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg", BASH),
    ("linux", "sudo apt install gh", BASH),
    ("macos", "brew install --cask visual-studio-code", ZSH),
    ("macos", "brew install git gh jq ripgrep fd fzf", ZSH),
    ("macos", "echo 'eval \"$(/opt/homebrew/bin/brew shellenv)\"' >> ~/.zprofile", ZSH),
    ("linux", "echo 'export PATH=\"$HOME/.cargo/bin:$PATH\"' >> ~/.bashrc", BASH),
    ("linux", "source $HOME/.cargo/env", BASH),
    ("linux", "rustup toolchain install nightly && rustup component add clippy rustfmt", BASH),
    ("linux", "cargo install ripgrep bat eza", BASH),
    ("linux", "go install golang.org/x/tools/gopls@latest", BASH),
    ("linux", "wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz", BASH),
    ("linux", "pip install --upgrade pip setuptools wheel", BASH),
    ("linux", "python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt", BASH),
    ("linux", "pipx install poetry", BASH),
    ("linux", "npm install -g typescript eslint prettier", BASH),
    ("linux", "npx create-next-app@latest my-app --typescript --tailwind --eslint", BASH),
    ("linux", "npm create vite@latest my-vue-app -- --template vue", BASH),
    ("linux", "corepack enable && corepack prepare pnpm@latest --activate", BASH),
    ("linux", "curl -s \"https://get.sdkman.io\" | bash", BASH),
    ("linux", "curl -sSL https://get.rvm.io | bash -s stable", BASH),
    ("linux", "curl https://pyenv.run | bash", BASH),
    ("linux", "curl -fsSL https://fnm.vercel.app/install | bash", BASH),
    ("linux", "curl -fsSL https://claude.ai/install.sh | bash", BASH),
    ("linux", "npm install -g @anthropic-ai/claude-code", BASH),
    ("linux", "curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.61.0", BASH),
    ("linux", "curl \"https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip\" -o \"awscliv2.zip\" && unzip awscliv2.zip && sudo ./aws/install", BASH),
    ("windows", "msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi", CMD),
    ("linux", "curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash", BASH),
    ("windows", "$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri https://aka.ms/installazurecliwindowsx64 -OutFile .\\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; Remove-Item .\\AzureCLI.msi", PS),
    ("linux", "wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg", BASH),
    ("linux", "sudo apt update && sudo apt install terraform", BASH),
    ("linux", "curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.24.0/kind-linux-amd64 && chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind", BASH),
    ("linux", "curl -LO https://storage.googleapis.com/minikube/latest/minikube-linux-amd64 && sudo install minikube-linux-amd64 /usr/local/bin/minikube", BASH),
    ("linux", "curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash", BASH),
    ("linux", "curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0", BASH),
    ("windows", "&powershell -NoProfile -ExecutionPolicy unrestricted -Command \"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; &([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1'))) -Channel 8.0\"", PS),
    ("linux", "curl -fsSL https://code-server.dev/install.sh | sh", BASH),
    ("linux", "curl -sSf https://atlasgo.sh | sh", BASH),
    ("linux", "curl -fsSL https://pkgx.sh | sh", BASH),
    ("linux", "curl -sS https://webi.sh/webi | sh", BASH),
    ("linux", "curl -fsSL https://fly.io/install.sh | sh", BASH),
    ("linux", "curl -sSL https://install.mondoo.com/sh | bash", BASH),
    ("linux", "curl -fsSL https://raw.githubusercontent.com/tj/n/master/bin/n | bash -s lts", BASH),
    ("linux", "sh <(curl -L https://nixos.org/nix/install) --daemon", BASH),
    ("linux", "curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install", BASH),
    ("linux", "curl -fsSL https://opencode.ai/install | bash", BASH),
    ("linux", "sudo snap install code --classic", BASH),
    ("linux", "flatpak install flathub org.mozilla.firefox", BASH),
    ("linux", "sudo dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm", BASH),
]

# Everyday work. (platform, text, origin, shell, role)
DAILY = [
    ("any", "git status", TERM, BASH, "engineering"),
    ("any", "git log --oneline --graph --decorate --all -n 30", TERM, BASH, "engineering"),
    ("any", "git rebase -i HEAD~5", U, BASH, "engineering"),
    ("any", "git reset --soft HEAD~1", U, BASH, "engineering"),
    ("any", "git push --force-with-lease origin feature/login", TERM, BASH, "engineering"),
    ("any", "git checkout -b fix/ci-cache && git push -u origin fix/ci-cache", TERM, BASH, "engineering"),
    ("any", "git config --global user.email \"dev@example.com\" && git config --global user.name \"Dev\"", U, BASH, "engineering"),
    ("any", "git remote set-url origin git@github.com:org/repo.git", U, BASH, "engineering"),
    ("any", "git submodule update --init --recursive", U, BASH, "engineering"),
    ("any", "git diff --stat main...HEAD", TERM, BASH, "engineering"),
    ("any", "git stash push -m wip && git pull --rebase && git stash pop", TERM, BASH, "engineering"),
    ("any", "git bisect start && git bisect bad && git bisect good v1.2.0", U, BASH, "engineering"),
    ("any", "git log -p -S'password' -- src/", U, BASH, "engineering"),
    ("any", "git clean -fdx", U, BASH, "engineering"),
    ("any", "gh pr checkout 1234", TERM, BASH, "engineering"),
    ("any", "gh run watch", TERM, BASH, "engineering"),
    ("any", "gh api repos/{owner}/{repo}/actions/runs --jq '.workflow_runs[0].status'", U, BASH, "engineering"),
    ("any", "docker ps -a --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'", U, BASH, "engineering"),
    ("any", "docker compose up -d --build", TERM, BASH, "engineering"),
    ("any", "docker compose logs -f --tail=100 api", TERM, BASH, "engineering"),
    ("any", "docker exec -it postgres psql -U postgres -d app", TERM, BASH, "engineering"),
    ("any", "docker system prune -af --volumes", U, BASH, "engineering"),
    ("any", "docker build -t registry.example.com/team/api:$(git rev-parse --short HEAD) .", TERM, BASH, "engineering"),
    ("any", "docker buildx build --platform linux/amd64,linux/arm64 -t org/app:latest --push .", U, BASH, "engineering"),
    ("any", "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image python:3.12-slim", U, BASH, "engineering"),
    ("any", "docker run -d --name redis -p 6379:6379 redis:7-alpine", U, BASH, "engineering"),
    ("any", "docker run --rm -it --entrypoint /bin/sh alpine:3.20", U, BASH, "engineering"),
    ("any", "kubectl get pods -A -o wide", TERM, BASH, "engineering"),
    ("any", "kubectl logs -f deploy/api -n prod --since=10m", TERM, BASH, "engineering"),
    ("any", "kubectl describe pod api-7d9f8c6b5-xk2lp -n prod", TERM, BASH, "engineering"),
    ("any", "kubectl rollout restart deployment/api -n staging", I, BASH, "engineering"),
    ("any", "kubectl port-forward svc/grafana 3000:80 -n monitoring", I, BASH, "engineering"),
    ("any", "kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}'", U, BASH, "engineering"),
    ("any", "kubectl exec -it deploy/api -n prod -- /bin/sh", I, BASH, "engineering"),
    ("any", "kubectl get secret regcred -o jsonpath='{.data.\\.dockerconfigjson}' | base64 --decode", U, BASH, "engineering"),
    ("any", "kubectl create secret generic api-key --from-literal=key=$(openssl rand -hex 32) -n prod", I, BASH, "engineering"),
    ("any", "kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml", V, BASH, "engineering"),
    ("any", "kubectl apply -k overlays/staging", TERM, BASH, "engineering"),
    ("any", "helm repo add bitnami https://charts.bitnami.com/bitnami && helm repo update", V, BASH, "engineering"),
    ("any", "helm upgrade --install ingress-nginx ingress-nginx --repo https://kubernetes.github.io/ingress-nginx --namespace ingress-nginx --create-namespace", V, BASH, "engineering"),
    ("any", "terraform init -upgrade && terraform plan -out tfplan", TERM, BASH, "engineering"),
    ("any", "terraform apply -auto-approve -var-file=prod.tfvars", I, BASH, "engineering"),
    ("any", "terraform state list | grep aws_security_group", TERM, BASH, "engineering"),
    ("any", "aws s3 sync ./dist s3://my-bucket/site --delete --cache-control max-age=300", I, BASH, "engineering"),
    ("any", "aws sts get-caller-identity", TERM, BASH, "engineering"),
    ("any", "aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com", V, BASH, "engineering"),
    ("any", "aws logs tail /aws/lambda/my-func --follow --since 1h", U, BASH, "engineering"),
    ("any", "gcloud auth login && gcloud config set project my-project-123", V, BASH, "engineering"),
    ("any", "gcloud container clusters get-credentials prod --region us-central1", I, BASH, "engineering"),
    ("any", "az login --use-device-code", V, BASH, "engineering"),
    ("any", "az aks get-credentials --resource-group rg-prod --name aks-prod", I, BASH, "engineering"),
    ("any", "ssh -L 5432:db.internal:5432 bastion.example.com -N", I, BASH, "engineering"),
    ("any", "ssh-keygen -t ed25519 -C \"dev@example.com\"", V, BASH, "engineering"),
    ("any", "ssh-copy-id -i ~/.ssh/id_ed25519.pub deploy@10.0.1.15", I, BASH, "engineering"),
    ("any", "scp -r ./build deploy@web01:/var/www/app/", TERM, BASH, "engineering"),
    ("any", "rsync -avz --progress --exclude node_modules ./ deploy@web01:/srv/app/", U, BASH, "engineering"),
    ("any", "openssl s_client -connect example.com:443 -servername example.com </dev/null | openssl x509 -noout -dates", U, BASH, "engineering"),
    ("any", "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj '/CN=localhost'", U, BASH, "engineering"),
    ("any", "openssl rand -base64 32", U, BASH, "engineering"),
    ("any", "echo -n 'admin:password' | base64", U, BASH, "engineering"),
    ("any", "echo 'eyJzdWIiOiIxMjM0NTY3ODkwIn0' | base64 -d", U, BASH, "engineering"),
    ("any", "cat ~/.docker/config.json | jq '.auths'", U, BASH, "engineering"),
    ("any", "sha256sum -c SHA256SUMS 2>&1 | grep OK", V, BASH, "engineering"),
    ("any", "gpg --verify archive.tar.gz.asc archive.tar.gz", V, BASH, "engineering"),
    ("any", "curl -I https://example.com", U, BASH, "engineering"),
    ("any", "curl -X POST -H 'Content-Type: application/json' -d '{\"name\":\"test\"}' http://localhost:8080/api/items", TERM, BASH, "engineering"),
    ("any", "curl -sS -u admin:$TOKEN https://jenkins.corp.example/job/build/lastBuild/api/json | jq .result", I, BASH, "engineering"),
    ("any", "curl -o /dev/null -s -w '%{http_code} %{time_total}\\n' https://example.com", U, BASH, "engineering"),
    ("any", "curl -fsSL https://raw.githubusercontent.com/org/repo/main/README.md -o README.md", U, BASH, "engineering"),
    ("any", "wget -r -np -nH --cut-dirs=3 -R 'index.html*' https://mirror.example.org/pub/data/", U, BASH, "engineering"),
    ("any", "wget -c https://releases.ubuntu.com/24.04/ubuntu-24.04.1-desktop-amd64.iso", V, BASH, "engineering"),
    ("any", "find . -name '*.log' -mtime +7 -exec rm {} \\;", U, BASH, "engineering"),
    ("any", "find . -type f -name '*.py' -not -path './.venv/*' | xargs wc -l | sort -n | tail", U, BASH, "engineering"),
    ("any", "grep -rn --include='*.ts' 'TODO' src/ | wc -l", TERM, BASH, "engineering"),
    ("any", "rg -n 'unsafe' --type rust crates/", TERM, BASH, "engineering"),
    ("any", "awk -F, 'NR>1 {sum+=$3} END {print sum/(NR-1)}' data.csv", U, BASH, "engineering"),
    ("any", "sed -i 's/old_name/new_name/g' $(grep -rl old_name src/)", U, BASH, "engineering"),
    ("any", "cat access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20", U, BASH, "engineering"),
    ("any", "tail -f /var/log/syslog | grep --line-buffered -i error", U, BASH, "engineering"),
    ("any", "journalctl -u nginx --since '1 hour ago' --no-pager", U, BASH, "engineering"),
    ("any", "sudo systemctl restart nginx && sudo systemctl status nginx --no-pager", U, BASH, "engineering"),
    ("any", "sudo systemctl enable --now docker", V, BASH, "engineering"),
    ("any", "sudo ufw allow 22/tcp && sudo ufw enable", U, BASH, "engineering"),
    ("any", "sudo lsof -i :8080", U, BASH, "engineering"),
    ("any", "ss -tulpn | grep LISTEN", U, BASH, "engineering"),
    ("any", "ps aux --sort=-%mem | head -n 15", U, BASH, "engineering"),
    ("any", "du -sh * | sort -h", U, BASH, "engineering"),
    ("any", "df -h && free -m", U, BASH, "engineering"),
    ("any", "sudo chown -R $USER:$USER ~/.npm", U, BASH, "engineering"),
    ("any", "chmod 600 ~/.ssh/id_ed25519", U, BASH, "engineering"),
    ("any", "tar -czvf backup-$(date +%F).tar.gz /etc/nginx", U, BASH, "engineering"),
    ("any", "tar -xJf node-v22.9.0-linux-x64.tar.xz -C ~/.local --strip-components=1", V, BASH, "engineering"),
    ("any", "unzip -q protoc-28.2-linux-x86_64.zip -d $HOME/.local", V, BASH, "engineering"),
    ("any", "ffmpeg -i input.mov -vf \"scale=1280:-2,fps=30\" -c:v libx264 -preset slow -crf 23 -c:a aac -b:a 128k -movflags +faststart output.mp4", U, BASH, "engineering"),
    ("any", "ffmpeg -ss 00:00:10 -i video.mp4 -frames:v 1 -q:v 2 thumb.jpg", U, BASH, "engineering"),
    ("any", "convert input.png -resize 50% -quality 85 output.jpg", U, BASH, "engineering"),
    ("any", "yt-dlp -f 'bv*+ba/b' --merge-output-format mp4 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'", U, BASH, "standard"),
    ("any", "python3 -m http.server 8000", U, BASH, "engineering"),
    ("any", "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'", U, BASH, "engineering"),
    ("any", "python -m pytest -x -vv tests/test_api.py::test_login", TERM, BASH, "engineering"),
    ("any", "python manage.py migrate && python manage.py runserver 0.0.0.0:8000", V, BASH, "engineering"),
    ("any", "uvicorn app.main:app --reload --host 0.0.0.0 --port 8000", V, BASH, "engineering"),
    ("any", "node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"", U, BASH, "engineering"),
    ("any", "npm ci && npm run build && npm test -- --coverage", TERM, BASH, "engineering"),
    ("any", "npm audit fix --force", U, BASH, "engineering"),
    ("any", "rm -rf node_modules package-lock.json && npm install", U, BASH, "engineering"),
    ("any", "yarn add -D @types/node vitest", V, BASH, "engineering"),
    ("any", "pnpm --filter web dev", TERM, BASH, "engineering"),
    ("any", "cargo build --release && ./target/release/app --help", TERM, BASH, "engineering"),
    ("any", "cargo clippy --all-targets --all-features -- -D warnings", TERM, BASH, "engineering"),
    ("any", "cargo test -- --nocapture --test-threads=1", TERM, BASH, "engineering"),
    ("any", "RUST_LOG=debug cargo run -- --config ./dev.toml", TERM, BASH, "engineering"),
    ("any", "go test ./... -race -count=1", TERM, BASH, "engineering"),
    ("any", "go mod tidy && go build -ldflags='-s -w' -o bin/app ./cmd/app", TERM, BASH, "engineering"),
    ("any", "make -j$(nproc) && sudo make install", U, BASH, "engineering"),
    ("any", "./configure --prefix=/usr/local && make && sudo make install", U, BASH, "engineering"),
    ("any", "cmake -B build -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && ninja -C build", U, BASH, "engineering"),
    ("any", "gcc -O2 -Wall -o hello hello.c && ./hello", U, BASH, "engineering"),
    ("any", "javac Main.java && java Main", U, BASH, "engineering"),
    ("any", "mvn clean package -DskipTests", U, BASH, "engineering"),
    ("any", "./gradlew build --scan", TERM, BASH, "engineering"),
    ("any", "psql -h localhost -U postgres -c 'SELECT pg_size_pretty(pg_database_size(current_database()));'", U, BASH, "engineering"),
    ("any", "pg_dump -Fc -h db.internal -U app app > app-$(date +%F).dump", I, BASH, "engineering"),
    ("any", "mysql -u root -p -e \"CREATE DATABASE app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\"", U, BASH, "engineering"),
    ("any", "redis-cli -h cache.internal --scan --pattern 'session:*' | head", I, BASH, "engineering"),
    ("any", "sqlite3 app.db '.tables'", U, BASH, "engineering"),
    ("any", "jq -r '.items[] | select(.status==\"failed\") | .id' results.json", U, BASH, "engineering"),
    ("any", "yq e '.spec.template.spec.containers[0].image' deployment.yaml", U, BASH, "engineering"),
    ("any", "watch -n 2 'kubectl get pods -n prod | grep -v Running'", U, BASH, "engineering"),
    ("any", "tmux new -s work", U, BASH, "engineering"),
    ("any", "nmap -sV -p 1-1000 192.168.1.0/24", U, BASH, "engineering"),
    ("any", "dig +short TXT _dmarc.example.com", U, BASH, "engineering"),
    ("any", "nslookup -type=mx example.com 8.8.8.8", U, BASH, "engineering"),
    ("any", "traceroute -n 1.1.1.1", U, BASH, "engineering"),
    ("any", "ip addr show && ip route", U, BASH, "engineering"),
    ("any", "sudo tcpdump -i any -nn port 53 -w dns.pcap", U, BASH, "engineering"),
    ("any", "crontab -l", U, BASH, "engineering"),
    ("any", "crontab -e", U, BASH, "engineering"),
    ("any", "export KUBECONFIG=~/.kube/config:~/.kube/staging && kubectl config get-contexts", U, BASH, "engineering"),
    ("any", "eval \"$(ssh-agent -s)\" && ssh-add ~/.ssh/id_ed25519", V, BASH, "engineering"),
    ("any", "eval \"$(direnv hook bash)\"", V, BASH, "engineering"),
    ("any", "eval \"$(pyenv init -)\"", V, BASH, "engineering"),
    ("any", "eval \"$(starship init zsh)\"", V, ZSH, "engineering"),
    ("any", "source ~/.zshrc", U, ZSH, "engineering"),
    ("any", "alias k=kubectl && complete -o default -F __start_kubectl k", V, BASH, "engineering"),
    ("any", "for f in *.png; do convert \"$f\" \"${f%.png}.webp\"; done", U, BASH, "engineering"),
    ("any", "while true; do curl -s localhost:8080/health; sleep 1; done", TERM, BASH, "engineering"),
    ("any", "xargs -a packages.txt sudo apt-get install -y", U, BASH, "engineering"),
    ("any", "sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y", U, BASH, "standard"),
    ("any", "sudo dnf upgrade --refresh", U, BASH, "standard"),
    ("any", "sudo pacman -Syu", U, BASH, "standard"),
    ("any", "flatpak update -y", U, BASH, "standard"),
    ("any", "nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv", U, BASH, "engineering"),
    ("any", "lsblk -f && sudo blkid", U, BASH, "engineering"),
    ("any", "sudo dd if=ubuntu.iso of=/dev/sdb bs=4M status=progress oflag=sync", U, BASH, "engineering"),
    ("any", "ollama run llama3.1:8b", V, BASH, "engineering"),
    ("any", "huggingface-cli download meta-llama/Llama-3.1-8B --local-dir ./models", V, BASH, "engineering"),
    ("any", "conda create -n ml python=3.11 -y && conda activate ml", V, BASH, "engineering"),
    ("any", "jupyter lab --no-browser --port 8888", U, BASH, "engineering"),
    ("any", "code --install-extension rust-lang.rust-analyzer", V, BASH, "engineering"),
    ("any", "vim +PlugInstall +qall", U, BASH, "engineering"),
    ("any", "curl -fLo ~/.vim/autoload/plug.vim --create-dirs https://raw.githubusercontent.com/junegunn/vim-plug/master/plug.vim", U, BASH, "engineering"),
    ("any", "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k", U, ZSH, "engineering"),
    ("any", "ansible-playbook -i inventory/prod site.yml --limit web --check --diff", I, BASH, "engineering"),
    ("any", "vault kv get -field=password secret/prod/db", I, BASH, "engineering"),
    ("any", "op read 'op://Private/GitHub/token'", V, BASH, "engineering"),
    ("any", "sops -d secrets.enc.yaml > secrets.yaml", U, BASH, "engineering"),
    ("any", "age -d -i key.txt secrets.age > secrets.env", U, BASH, "engineering"),
]

WINDOWS = [
    ("Get-Process | Sort-Object CPU -Descending | Select-Object -First 10", U, PS, "engineering"),
    ("Get-ChildItem -Path C:\\Logs -Recurse -Filter *.log | Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) | Remove-Item", U, PS, "admin"),
    ("Get-Service | Where-Object {$_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic'}", U, PS, "admin"),
    ("Restart-Service -Name Spooler -Force", I, PS, "admin"),
    ("Get-EventLog -LogName System -EntryType Error -Newest 20", U, PS, "admin"),
    ("Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 | Format-Table TimeCreated, Message -Wrap", U, PS, "admin"),
    ("Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)} | Select-Object Name, SamAccountName, LastLogonDate", I, PS, "admin"),
    ("Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name", I, PS, "admin"),
    ("Unlock-ADAccount -Identity jdoe", I, PS, "admin"),
    ("Set-ADAccountPassword -Identity jdoe -Reset -NewPassword (Read-Host -AsSecureString 'New password')", I, PS, "admin"),
    ("Connect-AzAccount -Tenant 00000000-0000-0000-0000-000000000000; Get-AzVM -Status | Select-Object Name, PowerState", V, PS, "admin"),
    ("Connect-MgGraph -Scopes 'User.Read.All','Group.ReadWrite.All'", V, PS, "admin"),
    ("Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled | Where-Object {-not $_.AccountEnabled}", V, PS, "admin"),
    ("Test-NetConnection -ComputerName sql01.corp.example -Port 1433", I, PS, "admin"),
    ("Resolve-DnsName -Name corp.example -Type MX", U, PS, "admin"),
    ("ipconfig /flushdns && ipconfig /registerdns", U, CMD, "standard"),
    ("netsh wlan show profiles", U, CMD, "standard"),
    ("sfc /scannow", U, CMD, "standard"),
    ("DISM /Online /Cleanup-Image /RestoreHealth", U, CMD, "standard"),
    ("chkdsk C: /f /r", U, CMD, "standard"),
    ("gpupdate /force", I, CMD, "standard"),
    ("gpresult /h C:\\Temp\\gp.html", I, CMD, "admin"),
    ("whoami /groups", U, CMD, "standard"),
    ("systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"", U, CMD, "standard"),
    ("tasklist /v | findstr /i chrome", U, CMD, "standard"),
    ("taskkill /IM OUTLOOK.EXE /F", I, CMD, "standard"),
    ("netstat -ano | findstr :443", U, CMD, "admin"),
    ("robocopy C:\\Data \\\\nas01\\backup\\Data /MIR /R:2 /W:5 /LOG:C:\\Temp\\robocopy.log", I, CMD, "admin"),
    ("xcopy /E /I /Y .\\dist \\\\web01\\c$\\inetpub\\wwwroot\\app", I, CMD, "admin"),
    ("schtasks /query /fo LIST /v", I, CMD, "admin"),
    ("wmic logicaldisk get name,freespace,size", U, CMD, "admin"),
    ("powercfg /batteryreport /output C:\\Temp\\battery.html", U, CMD, "standard"),
    ("winget upgrade --all --silent", U, PS, "standard"),
    ("choco upgrade all -y", V, PS, "admin"),
    ("choco install googlechrome 7zip vscode -y", V, PS, "admin"),
    ("scoop install git nodejs-lts", V, PS, "engineering"),
    ("Get-FileHash .\\setup.exe -Algorithm SHA256", U, PS, "engineering"),
    ("Get-AuthenticodeSignature .\\setup.exe | Format-List", U, PS, "engineering"),
    ("Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.4.5/PowerShell-7.4.5-win-x64.msi -OutFile $env:USERPROFILE\\Downloads\\pwsh.msi", U, PS, "engineering"),
    ("Invoke-RestMethod -Uri https://api.github.com/repos/microsoft/terminal/releases/latest | Select-Object tag_name", U, PS, "engineering"),
    ("$env:Path += ';C:\\tools\\bin'; [Environment]::SetEnvironmentVariable('Path', $env:Path, 'User')", U, PS, "engineering"),
    ("New-Item -ItemType SymbolicLink -Path C:\\Users\\dev\\.config -Target D:\\dotfiles\\.config", U, PS, "engineering"),
    ("Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All", V, PS, "admin"),
    ("dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart", V, PS, "engineering"),
    ("Set-MpPreference -ExclusionPath 'D:\\src'", U, PS, "engineering"),
    ("Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated", U, PS, "admin"),
    ("Update-MpSignature", U, PS, "admin"),
    ("Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus", I, PS, "admin"),
    ("manage-bde -status C:", I, CMD, "admin"),
    ("Install-WindowsFeature -Name Web-Server -IncludeManagementTools", V, PS, "admin"),
    ("Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Enable-NetFirewallRule", U, PS, "admin"),
    ("Enter-PSSession -ComputerName srv01 -Credential (Get-Credential)", I, PS, "admin"),
    ("Invoke-Command -ComputerName (Get-Content servers.txt) -ScriptBlock { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 }", I, PS, "admin"),
    ("Get-Content .\\app.log -Tail 50 -Wait", U, PS, "engineering"),
    ("Select-String -Path .\\*.log -Pattern 'Exception' | Group-Object Filename | Sort-Object Count -Descending", U, PS, "engineering"),
    ("Compress-Archive -Path .\\publish\\* -DestinationPath .\\release.zip -Force", U, PS, "engineering"),
    ("dotnet new webapi -n MyApi && cd MyApi && dotnet run", V, PS, "engineering"),
    ("dotnet tool install --global dotnet-ef", V, PS, "engineering"),
    ("npm config set script-shell \"C:\\Program Files\\Git\\bin\\bash.exe\"", U, PS, "engineering"),
    ("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced /v HideFileExt /t REG_DWORD /d 0 /f", U, CMD, "standard"),
    ("reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\" /v LongPathsEnabled /t REG_DWORD /d 1 /f", U, CMD, "engineering"),
    ("Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0", I, PS, "admin"),
    ("rundll32.exe sysdm.cpl,EditEnvironmentVariables", U, "run_dialog", "engineering"),
    ("control /name Microsoft.ProgramsAndFeatures", U, "run_dialog", "standard"),
    ("ms-settings:windowsupdate", U, "run_dialog", "standard"),
    ("%appdata%", U, "run_dialog", "standard"),
    ("%temp%", U, "run_dialog", "standard"),
    ("shell:startup", U, "run_dialog", "standard"),
    ("msconfig", U, "run_dialog", "standard"),
    ("devmgmt.msc", U, "run_dialog", "standard"),
    ("\\\\fs01\\shared\\IT", I, "run_dialog", "standard"),
    ("cmd", U, "run_dialog", "standard"),
    ("powershell", U, "run_dialog", "standard"),
    ("mstsc /v:jumpbox.corp.example", I, "run_dialog", "admin"),
    ("certutil -store -user My", I, CMD, "admin"),
    ("certutil -verify -urlfetch .\\server.cer", I, CMD, "admin"),
    ("bitsadmin /list /allusers /verbose", I, CMD, "admin"),
    ("powershell -NoProfile -Command \"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, LastBootUpTime\"", U, CMD, "admin"),
]

SECRETS = [
    (SSHKEY, VSC),
    ("ghp_EXAMPLE1A2b3C4d5E6f7G8h9", "application:firefox"),
    ("sk-EXAMPLE-Xq9vZ2mL8kP4wR7tY1uI6oE3aS5dF0gH2jK4lZ8xC6vB9nM1qW-AbCdEf", "application:firefox"),
    ("AKIAIOSFODNN7EXAMPLE", VSC),
    ("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", VSC),
    ("xoxb-EXAMPLE-EXAMPLE-AbCdEfGhIjKlMnOpQrStUvWx", "application:slack"),
    ("{\"auths\":{\"ghcr.io\":{\"auth\":\"dXNlcjpnaHBfMUEyYjNDNGQ1RTZmN0c4aDlJMGpLMWxNMm5PM3BRNHJTNXRV\"}}}", VSC),
    ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==", VSC),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", TERM),
    ("d41d8cd98f00b204e9800998ecf8427e", TERM),
    ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", TERM),
    ("$2b$12$KIXQJxj8yZ6P9QzW7GzF0eQwQh3u5c8j8bXx2rQe7dK1m9ZqXyZ1e", VSC),
    ("-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBGBxAbcBEADGx7kL2pQ9vR3tY8wE1uI5oP0aS6dF4gH7jK2lZ9xC3vB8nM0q\n-----END PGP PUBLIC KEY BLOCK-----", "application:firefox"),
    ("{\"type\":\"service_account\",\"project_id\":\"my-project\",\"private_key_id\":\"a1b2c3d4e5f6\",\"client_email\":\"svc@my-project.iam.gserviceaccount.com\"}", VSC),
    ("H4sIAAAAAAAAA6tWSkksSVSyUlAqzy/KSVFIzs8rSc0rUcjMS8svyk0tAgCHbTb3IAAAAA==", VSC),
    ("terraform.tfstate: {\"version\":4,\"terraform_version\":\"1.9.5\",\"serial\":42,\"lineage\":\"3f2c1a9e-8b7d-4c6e-a5f4-0d1e2f3a4b5c\"}", VSC),
    ("NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijkl.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.abc123", VSC),
    ("Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20ifQ.c2lnbmF0dXJl", "application:firefox"),
    ("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "application:firefox"),
    ("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "application:firefox"),
]

PROSE = [
    "Hi team, the deploy is scheduled for 3pm. Please verify your changes are merged by noon.",
    "Meeting notes: discussed Q3 roadmap, action items for Alice and Bob, follow up on the captcha vendor contract.",
    "https://docs.google.com/document/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ/edit",
    "https://github.com/org/repo/pull/1234#issuecomment-987654321",
    "Your verification code is 482913. It expires in 10 minutes.",
    "1600 Pennsylvania Avenue NW, Washington, DC 20500",
    "SELECT u.id, u.email, COUNT(o.id) FROM users u LEFT JOIN orders o ON o.user_id = u.id GROUP BY u.id HAVING COUNT(o.id) > 5;",
    "def fib(n):\n    return n if n < 2 else fib(n-1) + fib(n-2)",
    "const res = await fetch('/api/items', { method: 'POST', body: JSON.stringify(item) });",
    "import subprocess\nsubprocess.run(['ls', '-la'], check=True)",
    "#!/usr/bin/env bash\nset -euo pipefail\necho \"building $1\"",
    "error[E0502]: cannot borrow `v` as mutable because it is also borrowed as immutable",
    "Traceback (most recent call last):\n  File \"app.py\", line 12, in <module>\n    main()\nKeyError: 'user_id'",
    "Order #A-20931 confirmed. Tracking: 1Z999AA10123456784",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore.",
]

# Multi-line terminal output and config: an interpreter is named somewhere and the rest is
# data. Synthetic, modelled on a real false positive from a pasted AWS CLI session.
TERMINAL_OUTPUT = [
    """~ $ aws lambda get-function-configuration --function-name f --query "$Q"
{
    "run": "python3.13",
    "role": "arn:aws:iam::111122223333:role/example-password-recovery-trigger",
    "env": [
        "REVOCATION_BUCKET",
        "USER_POOL_ID"
    ]
}
~ $ aws lambda get-policy --function-name f --query Policy --output text | jq .
{
  "Statement": [
    {
      "Sid": "CognitoRecoveryInvoke",
      "Resource": "arn:aws:lambda:us-east-1:111122223333:function:example-password-recovery",
      "Condition": {
        "StringEquals": {
          "AWS:SourceAccount": "111122223333"
        }
      }
    }
  ]
}""",
    """$ kubectl get pods -o wide
NAME                     READY   STATUS    RESTARTS   AGE   IP           NODE
api-7c9d8f6b5d-x2x9k     1/1     Running   0          3d    10.0.3.14    node-a
worker-6f7c5d9b8-qwz4p   1/1     Running   2          3d    10.0.3.27    node-b
$ kubectl describe pod worker-6f7c5d9b8-qwz4p | grep -A2 Command
    Command:
      python3
      worker.py""",
    """Traceback (most recent call last):
  File "/usr/lib/python3.12/runpy.py", line 198, in _run_module_as_main
    return _run_code(code, main_globals, None,
  File "/srv/app/auth.py", line 41, in verify_token
    raise ValueError("token validation failed, confirm the identifier")
ValueError: token validation failed, confirm the identifier""",
    """● app.service - Example API
     Loaded: loaded (/etc/systemd/system/app.service; enabled; preset: enabled)
     Active: active (running) since Tue 2026-11-03 09:12:44 UTC; 1 day ago
   Main PID: 2211 (python3)
     CGroup: /system.slice/app.service
             └─2211 /usr/bin/python3 -m uvicorn app:api --port 8000
Nov 04 10:01:12 host python3[2211]: INFO        GET /health 200 reference id 8841""",
    """{
  "name": "example-app",
  "scripts": {
    "test": "bash scripts/test.sh",
    "lint": "eslint ."
  },
  "dependencies": {
    "express": "^4.19.2"
  },
  "repository": {
    "url": "git+https://github.com/example/example-app.git"
  }
}""",
    """services:
  api:
    image: registry.example.com/team/api:1.42.0
    command: ["python3", "-m", "uvicorn", "app:api"]
    environment:
      - AUTH_VERIFY_URL=https://auth.example.com/verify
      - LOG_LEVEL=info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s""",
    """$ git log --oneline -4
a1b2c3d fix: confirm webhook signature before parsing
9f8e7d6 build: bump python base image to 3.13
1234abc docs: update identifier reference
$ pip list | grep -i boto
boto3                 1.35.2
botocore              1.35.2""",
    """#!/usr/bin/env bash
set -euo pipefail
# Verify the release artifact before uploading it
sha256sum -c release.sha256
# Confirm the tag matches the version file
test "$(git describe --tags)" = "v$(cat VERSION)"
gh release upload "$(git describe --tags)" dist/*""",
    """$ docker ps
CONTAINER ID   IMAGE         COMMAND                  CREATED        STATUS        NAMES
3f2a1b9c8d7e   nginx:1.27    "/docker-entrypoint.…"   2 hours ago    Up 2 hours    web
8e7d6c5b4a3f   python:3.13   "python3 worker.py"      2 hours ago    Up 2 hours    worker""",
    """Run python3 -m pytest -q
........................................................ [ 96%]
..                                                       [100%]
58 passed in 2.41s
Post job cleanup.
Removing authentication credentials and verifying workspace state""",
]

HEADER = ["id", "category", "platform", "text", "origin", "target", "role", "bypass_risk", "source_row", "notes"]


def main():
    rows = []
    for i, r in enumerate(PART1, 1):
        cat, plat, text, origin, target, role, risk, src, notes = r
        rows.append([f"B{i:03d}", cat, plat, text, origin, target, role, risk, src, notes])
    n = len(rows)

    def add(cat, plat, text, origin, target, role, risk="", src="", notes=""):
        nonlocal n
        n += 1
        rows.append([f"B{n:03d}", cat, plat, text, origin, target, role, risk, src, notes])

    for plat, text, shell in INSTALL:
        add("install_docs", plat, text, V, shell, "engineering", notes="copied from the tool's own docs")
    for plat, text, origin, shell, role in DAILY:
        add("dev_daily", plat, text, origin, shell, role)
    for text, origin, target, role in WINDOWS:
        add("windows_admin", "windows", text, origin, target, role)
    for text, origin in SECRETS:
        add("secret_or_blob", "any", text, origin, "unknown", "engineering")
    for text in PROSE:
        add("prose_or_code", "any", text, "application:firefox", "unknown", "standard")

    for text in TERMINAL_OUTPUT:
        add("terminal_output", "any", text, "unknown", "unknown", "engineering")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "corpus", "benign.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(HEADER)
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
