$env:PYTHONIOENCODING="utf-8"
Write-Host "Running Basic Block/Allow Test..."
python test_agent.py
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "Running Rate Limit Test..."
python test_ratelimit.py
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "Running Asyncpg Test..."
python test_asyncpg.py
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "Running Webhook Test..."
python test_webhook.py
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "Running Masking Bypass Test..."
python test_masking_bypass.py
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "ALL TESTS PASSED"
