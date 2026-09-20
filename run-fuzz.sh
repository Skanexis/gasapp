#!/usr/bin/env bash
# Прогон всех таргетов фаззинга внутри контейнера.
#
# Печатает по строке на таргет: сколько итераций выполнено и нашлось ли
# падение. Именно эти числа идут в план — «фаззинг запускали» без числа
# итераций ничего не значит.
set -uo pipefail

SECONDS_PER_TARGET="${SECONDS_PER_TARGET:-120}"

cd /work

targets=$(ls fuzz/fuzz_targets/*.rs | xargs -n1 basename | sed 's/\.rs$//')

echo "таргетов: $(echo "$targets" | wc -l), по ${SECONDS_PER_TARGET} с на каждый"
echo

total=0
failed=0

for t in $targets; do
  log="/tmp/$t.log"

  # -runs: без предела libFuzzer идёт вечно; -max_total_time даёт
  # воспроизводимый бюджет по времени.
  cargo +nightly fuzz run --fuzz-dir fuzz "$t" -- \
    -max_total_time="$SECONDS_PER_TARGET" \
    -print_final_stats=1 \
    > "$log" 2>&1

  status=$?

  # Итоговая статистика libFuzzer: "stat::number_of_executed_units: N".
  runs=$(grep -oE "stat::number_of_executed_units:[[:space:]]*[0-9]+" "$log" \
         | grep -oE "[0-9]+$" | tail -1)
  runs="${runs:-0}"

  total=$((total + runs))

  if [ "$status" -ne 0 ]; then
    echo "❌ $t — падение (итераций: $runs)"
    tail -25 "$log"
    failed=$((failed + 1))
  else
    echo "✅ $t — итераций: $runs"
  fi
done

echo
echo "итого итераций: $total"
echo "таргетов с падениями: $failed"

exit "$failed"
