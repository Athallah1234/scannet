# NetScan PyPI Upload Script

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "       NetScan PyPI Upload Utility            " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# 1. Clean previous build artifacts
Write-Host "`nCleaning old build artifacts..." -ForegroundColor Yellow
$pathsToClean = "build", "dist", "scannet.egg-info"
foreach ($path in $pathsToClean) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force
    }
}

# 2. Check and Install build/twine dependencies
Write-Host "`nEnsuring build and twine dependencies are installed..." -ForegroundColor Yellow
python -m pip install --upgrade pip build twine

# 3. Build source distribution and wheel
Write-Host "`nBuilding distribution packages (source and wheel)..." -ForegroundColor Yellow
python -m build

# 4. Check package integrity
Write-Host "`nChecking package integrity..." -ForegroundColor Yellow
python -m twine check dist/*

# 5. Choose PyPI Repository and upload
Write-Host "`nChoose PyPI repository target:" -ForegroundColor Yellow
Write-Host "1) Real PyPI (production)"
Write-Host "2) TestPyPI (testing environment)"
$choice = Read-Host "Select option [1-2]"

if ($choice -eq "2") {
    Write-Host "`nUploading to TestPyPI..." -ForegroundColor Green
    python -m twine upload --repository testpypi dist/*
} else {
    Write-Host "`nUploading to Real PyPI (using local .pypirc)..." -ForegroundColor Green
    python -m twine upload --config-file .pypirc dist/*
}

Write-Host "`nFinished upload process!" -ForegroundColor Cyan
