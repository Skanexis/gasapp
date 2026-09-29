#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# fetch-module <модуль> <каталог> — последняя версия Go-модуля через
# GOPROXY в каталог, пригодный для сборки. Не `go install`: у модулей
# Tor Project есть директивы replace, а с ними он не работает.
set -eu
dir=$(go mod download -json "$1@latest" | sed -n 's/.*"Dir": "\(.*\)".*/\1/p')
test -n "$dir"
cp -r "$dir" "$2"
chmod -R u+w "$2"
