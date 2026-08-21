# SPDX-License-Identifier: Apache-2.0
#
# Прогон всех фаззинг-таргетов в контейнере.
#
# Зачем контейнер: libFuzzer требует clang-совместимых санитайзеров,
# а x64-библиотеки ASan в составе Visual Studio Build Tools 2019
# отсутствуют — сборка на хосте падает на линковке. Подробности
# в fuzz/README.md.
#
# Использование:
#   pwsh fuzz/run-all.ps1                  # 300 секунд на таргет
#   pwsh fuzz/run-all.ps1 -Seconds 3600    # часовой прогон

param(
    [int]$Seconds = 300,
    [string]$Image = "aegis-fuzz:latest"
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$targets = @(
    "chunk_reassembly",
    "parse_message",
    "decrypt_session",
    "parse_prekey_bundle",
    "parse_session_state",
    "parse_safety_number"
)

if (-not (docker images -q $Image)) {
    Write-Host "Образ $Image не найден, собираю..."
    docker build -f "$repo\fuzz\Dockerfile" -t $Image "$repo\fuzz"
}

$failed = @()

foreach ($target in $targets) {
    Write-Host ""
    Write-Host "=== $target ($Seconds c) ===" -ForegroundColor Cyan

    docker run --rm -v "${repo}:/aegis" $Image `
        run --fuzz-dir fuzz $target -- `
        "-max_total_time=$Seconds" -rss_limit_mb=4096

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ПАДЕНИЕ: $target" -ForegroundColor Red
        $failed += $target
    }
}

Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host "Упали таргеты: $($failed -join ', ')" -ForegroundColor Red
    Write-Host "Входы, воспроизводящие краш, — в fuzz/artifacts/"
    exit 1
}

Write-Host "Все таргеты прошли без крашей." -ForegroundColor Green
