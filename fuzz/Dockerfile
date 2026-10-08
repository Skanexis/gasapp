# SPDX-License-Identifier: Apache-2.0
#
# Контейнер для прогона фаззинга.
#
# Зачем контейнер, а не хост. libFuzzer требует clang-совместимых
# санитайзеров. На Windows MSVC x64-библиотеки ASan (`clang_rt.asan_*`)
# в составе Build Tools 2019 отсутствуют, и сборка падает на этапе
# линковки. Linux-образ решает это без установки чего-либо на машину
# разработчика и заодно повторяет окружение ночного CI.

FROM rust:1-slim-bookworm

# `cargo-fuzz` собирает таргеты nightly-компилятором: инструментирование
# покрытия (`-C passes=sancov-module`) на стабильном канале недоступно.
RUN rustup toolchain install nightly --profile minimal \
    && rustup component add llvm-tools-preview --toolchain nightly

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-fuzz --locked

WORKDIR /gasapp

# Исходники монтируются, а не копируются: прогон идёт по текущему дереву,
# и корпус, накопленный внутри, остаётся на хосте.
ENTRYPOINT ["cargo", "+nightly", "fuzz"]
