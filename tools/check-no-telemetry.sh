#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Правило 7 (GASAPP_MASTER_PLAN.md §4.1): нет телеметрии, нет аналитики.
#
# Ноль сторонних SDK для аналитики, рекламы и краш-репортинга.
# Крашлог мессенджера может содержать фрагменты открытого текста и ключевой
# материал; отправка его третьей стороне сводит на нет всё остальное.

set -euo pipefail

# Имена SDK ищутся с начала слова: иначе «Segment» находился в обычном
# `lastSegment`, и проверка краснела на коде, где телеметрии нет.
FORBIDDEN='(FirebaseAnalytics|Crashlytics|firebase-analytics|firebase-crashlytics|com\.google\.android\.gms\.analytics|GoogleAnalytics|Amplitude|Mixpanel|AppsFlyer|Adjust\.|Braze|Segment|Bugsnag|Sentry|AppCenter|Flurry|Countly|OneSignal|FacebookSDK|AdMob|com\.applovin|UnityAds)'

# foss-flavor Android дополнительно обязан не содержать Google Play Services
FORBIDDEN_FOSS='com\.google\.android\.gms|com\.google\.firebase'

violations=0

echo "== Правило 7: поиск SDK телеметрии и рекламы =="

hits=$(grep -rnE "$FORBIDDEN" \
        --include='*.swift' --include='*.kt' --include='*.kts' \
        --include='*.gradle' --include='*.plist' --include='*.toml' \
        --include='*.json' --include='Podfile' \
        ios android crates 2>/dev/null || true)

if [ -n "$hits" ]; then
  echo "::error::найдены запрещённые SDK телеметрии/аналитики/рекламы:"
  echo "$hits"
  echo ""
  echo "  Раздел 4.2 главного документа запрещает их без исключений."
  violations=$((violations + 1))
else
  echo "OK: SDK телеметрии не найдено"
fi

echo ""
echo "== foss-flavor: отсутствие Google Play Services =="

foss_dir="android/app/src/foss"
if [ -d "$foss_dir" ]; then
  foss_hits=$(grep -rnE "$FORBIDDEN_FOSS" "$foss_dir" 2>/dev/null || true)
  if [ -n "$foss_hits" ]; then
    echo "::error::foss-сборка ссылается на Google Play Services:"
    echo "$foss_hits"
    violations=$((violations + 1))
  else
    echo "OK: foss-сборка свободна от GMS"
  fi
else
  echo "SKIP: каталог $foss_dir ещё не создан (появится в M1)"
fi

exit "$violations"
