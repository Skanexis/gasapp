#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Версия NDK закреплена в двух местах и обязана совпадать.
#
# # Почему это важно
#
# ADR-020 (воспроизводимые сборки) требует, чтобы одна и та же ревизия
# давала байт в байт одинаковый APK. В libgasapp.so участвуют **оба**
# закрепления:
#
#   * tools/Dockerfile.android — этим NDK библиотека **собирается**;
#   * android/app/build.gradle — этим NDK она **обрезается** (strip).
#
# Разные версии дают разный результат обеих операций, и сборка
# разработчика перестаёт совпадать со сборкой CI. Заметить это без
# проверки нельзя: обе сборки успешны, отличаются только байты.
#
# # Почему проверка отдельная, а не одна переменная на оба файла
#
# Gradle и Dockerfile читают конфигурацию по-разному и общей переменной
# не имеют. Вынести её во внешний файл можно, но тогда каждый из двух
# перестал бы быть самодостаточным: Dockerfile обязан собираться
# в отрыве от репозитория.
#
# # Как соотносятся обозначения
#
# NDK публикуется под двумя именами: r27c и 27.2.12479018. Dockerfile
# качает архив по первому, Gradle ищет каталог SDK по второму.
# Соответствие захардкожено в таблице ниже — вывести его неоткуда.

set -euo pipefail

echo "== Версия NDK закреплена одинаково =="

# Соответствие r-имён и версий пакета SDK.
declare -A RELEASE_TO_VERSION=(
  ["r26d"]="26.3.11579264"
  ["r27b"]="27.1.12297006"
  ["r27c"]="27.2.12479018"
  ["r28"]="28.0.12674087"
)

docker_release=$(sed -n 's/^ARG NDK_VERSION=\(.*\)$/\1/p' tools/Dockerfile.android | head -1)
gradle_version=$(sed -n 's/^[[:space:]]*ndkVersion = "\(.*\)"$/\1/p' android/app/build.gradle | head -1)

if [[ -z "$docker_release" ]]; then
  echo "❌ не найден ARG NDK_VERSION в tools/Dockerfile.android" >&2
  exit 1
fi

if [[ -z "$gradle_version" ]]; then
  echo "❌ не найден ndkVersion в android/app/build.gradle" >&2
  exit 1
fi

expected="${RELEASE_TO_VERSION[$docker_release]:-}"

if [[ -z "$expected" ]]; then
  echo "❌ NDK $docker_release неизвестен этой проверке" >&2
  echo "   добавьте его в таблицу RELEASE_TO_VERSION в $0" >&2
  exit 1
fi

echo "  Dockerfile : $docker_release ($expected)"
echo "  build.gradle: $gradle_version"

if [[ "$expected" != "$gradle_version" ]]; then
  echo >&2
  echo "❌ версии NDK разошлись" >&2
  echo "   контейнер собирает libgasapp.so одним NDK, Gradle обрезает её другим —" >&2
  echo "   APK разработчика и APK из CI перестанут совпадать байт в байт" >&2
  exit 1
fi

echo "✅ совпадают"
