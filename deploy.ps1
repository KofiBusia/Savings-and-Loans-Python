# Ghana Savings & Loans — One-Command Deploy Script
# Usage: .\deploy.ps1
# Lints, runs compliance tests, commits, and pushes to GitHub.
# Requires: git, Python 3.11+, pip

param(
    [string]$Message = "",
    [switch]$SkipTests = $false,
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"
$REPO_URL = "https://github.com/KofiBusia/Savings-and-Loans-Python.git"

function Write-Step { param($text) Write-Host "`n==> $text" -ForegroundColor Cyan }
function Write-OK   { param($text) Write-Host "[OK] $text" -ForegroundColor Green }
function Write-Fail { param($text) Write-Host "[FAIL] $text" -ForegroundColor Red; exit 1 }

Write-Step "Ghana Savings & Loans — Deploy Script"
Write-Host "  Repo: $REPO_URL"
Write-Host "  Path: $(Get-Location)"

# ── 1. Check Python ──────────────────────────────────────────────────────────
Write-Step "Checking Python version"
$pyVersion = python --version 2>&1
if (-not ($pyVersion -match "3\.(11|12|13)")) {
    Write-Fail "Python 3.11+ required. Found: $pyVersion"
}
Write-OK $pyVersion

# ── 2. Activate / create venv ─────────────────────────────────────────────────
Write-Step "Setting up virtual environment"
if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-OK "venv created"
}
.\venv\Scripts\Activate.ps1
Write-OK "venv activated"

# ── 3. Install dependencies ───────────────────────────────────────────────────
Write-Step "Installing dependencies"
pip install -r requirements.txt --quiet
Write-OK "Dependencies installed"

# ── 4. Lint ───────────────────────────────────────────────────────────────────
Write-Step "Running Ruff lint"
$lintResult = ruff check . 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $lintResult -ForegroundColor Yellow
    if (-not $Force) { Write-Fail "Lint errors found. Fix or run with -Force to override." }
    Write-Host "[WARN] Lint errors ignored (--Force used)" -ForegroundColor Yellow
} else {
    Write-OK "Lint passed"
}

# ── 5. Compliance Tests (BUILD GATE) ─────────────────────────────────────────
if (-not $SkipTests) {
    Write-Step "Running Ghana Compliance Tests (BUILD GATE)"
    $env:NODE_ENV = "test"
    $env:DATABASE_URL = "sqlite:///./test.db"
    $env:SECRET_KEY = "test-secret-key-not-for-production"
    $env:MOCK_GHIPSS = "true"
    $env:MOCK_CREDIT_BUREAUS = "true"
    $env:MOCK_GHANA_CARD_API = "true"

    pytest tests/test_compliance_guards.py -v --tb=short
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "COMPLIANCE TESTS FAILED. Deployment blocked. Fix compliance violations before pushing."
    }
    Write-OK "All compliance tests passed"
} else {
    Write-Host "[WARN] Compliance tests skipped (-SkipTests). NOT RECOMMENDED." -ForegroundColor Yellow
}

# ── 6. Git setup ──────────────────────────────────────────────────────────────
Write-Step "Checking git repository"
if (-not (Test-Path ".git")) {
    git init
    git remote add origin $REPO_URL
    Write-OK "Git repo initialised"
} else {
    $remotes = git remote -v 2>&1
    if (-not ($remotes -match "Savings-and-Loans-Python")) {
        git remote add origin $REPO_URL
    }
    Write-OK "Git repo ready"
}

# ── 7. Stage & commit ─────────────────────────────────────────────────────────
Write-Step "Staging changes"
git add -A

$status = git status --porcelain
if (-not $status) {
    Write-OK "Nothing to commit — working tree clean"
} else {
    if (-not $Message) {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm"
        $Message = "deploy: automated push $ts (compliance tests passed)"
    }
    git commit -m $Message
    Write-OK "Committed: $Message"
}

# ── 8. Push to GitHub ─────────────────────────────────────────────────────────
Write-Step "Pushing to GitHub"
git branch -M main
git push -u origin main
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Push failed. Check GitHub credentials and repo access."
}
Write-OK "Pushed to $REPO_URL"

# ── 9. Done ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=" * 62 -ForegroundColor Green
Write-Host "  DEPLOY COMPLETE" -ForegroundColor Green
Write-Host "  Repository: $REPO_URL" -ForegroundColor Green
Write-Host "  GitHub Actions CI/CD will now run compliance tests & deploy." -ForegroundColor Green
Write-Host "=" * 62 -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Check GitHub Actions: https://github.com/KofiBusia/Savings-and-Loans-Python/actions"
Write-Host "  2. Set GitHub Secrets: SECRET_KEY, DATABASE_URL, RENDER_DEPLOY_HOOK_URL, etc."
Write-Host "  3. Apply for BoG pre-approval using docs/BOG_PREAPPROVAL.md"
