param(
    [string]$QtRoot = 'D:\QT\Qt5.12.12',
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$qtBin = Join-Path $QtRoot '5.12.12\mingw73_64\bin'
$compilerBin = Join-Path $QtRoot 'Tools\mingw730_64\bin'
$env:Path = "$compilerBin;$qtBin;" + $env:Path
function Invoke-Checked([string]$exe, [string[]]$arguments) {
    & $exe @arguments
    if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}
$buildDir = Join-Path $projectRoot 'build'
$testDir = Join-Path $buildDir 'tests'
$stageDir = Join-Path $projectRoot 'deploy\NetworkDoctor'
New-Item -ItemType Directory -Force -Path $buildDir,$testDir,$stageDir | Out-Null
Push-Location $buildDir
try {
    Invoke-Checked (Join-Path $qtBin 'qmake.exe') @((Join-Path $projectRoot 'NetworkDoctor.pro'), '-spec', 'win32-g++', 'CONFIG+=release')
    Invoke-Checked (Join-Path $compilerBin 'mingw32-make.exe') @('-j4')
} finally { Pop-Location }
Copy-Item -LiteralPath (Join-Path $buildDir 'release\NetworkDoctor.exe') -Destination $stageDir -Force
if (!(Test-Path (Join-Path $stageDir 'targets.json'))) { Copy-Item -LiteralPath (Join-Path $projectRoot 'config\targets.json') -Destination $stageDir }
Invoke-Checked (Join-Path $qtBin 'windeployqt.exe') @('--release','--compiler-runtime','--no-translations',(Join-Path $stageDir 'NetworkDoctor.exe'))
foreach ($dll in @('libssl-1_1-x64.dll','libcrypto-1_1-x64.dll')) {
    Copy-Item -LiteralPath (Join-Path $QtRoot "Tools\QtCreator\bin\$dll") -Destination $stageDir -Force
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination $stageDir -Force
# Prove the staged app can load TLS without Qt/MinGW directories in PATH.
$buildPath = $env:Path
try {
    $env:Path = "$env:SystemRoot\System32;$env:SystemRoot"
    $selfCheckPath = Join-Path $buildDir 'tls-self-check.json'
    $checkProcess = Start-Process -FilePath (Join-Path $stageDir 'NetworkDoctor.exe') -ArgumentList @('--self-check','--output',('"' + $selfCheckPath + '"')) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    if (!$checkProcess.WaitForExit(15000)) { Stop-Process -Id $checkProcess.Id; throw 'TLS self-check timed out' }
    if ($checkProcess.ExitCode -ne 0) { throw "Bundled TLS self-check failed: $selfCheckPath" }
} finally { $env:Path = $buildPath }
if (!$SkipTests) {
    Push-Location $testDir
    try {
        Invoke-Checked (Join-Path $qtBin 'qmake.exe') @((Join-Path $projectRoot 'tests\tests.pro'),'-spec','win32-g++','CONFIG+=release')
        Invoke-Checked (Join-Path $compilerBin 'mingw32-make.exe') @('-j4')
        $env:Path = "$stageDir;" + $env:Path
        $testOutput = (Join-Path $buildDir 'test-results.txt') + ',txt'
        Invoke-Checked (Join-Path $testDir 'release\doctor_tests.exe') @('-o',$testOutput)
    } finally { Pop-Location }
}
Write-Output "Release ready: $stageDir"
