# SPDX-License-Identifier: Apache-2.0
"""Обёртка над движком `gasapp-bot` для ботов на Python.

Запускает движок дочерним процессом и разговаривает с ним строками
JSON (см. docs/bots.md). Сторонних зависимостей нет.

    bot = Bot("./mybot")
    for event in bot.events():
        if event["event"] == "message":
            bot.call("sendMessage", to=event["from"], text="привет")
"""

import json
import subprocess


class BotError(Exception):
    """Движок ответил отказом; `code` — короткое слово ошибки."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Bot:
    def __init__(self, data_dir, program="gasapp-bot", poll_seconds=5):
        self._process = subprocess.Popen(
            [program, "run", "--data", data_dir, "--poll", str(poll_seconds)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        self._next_id = 0
        # События, пришедшие, пока ждали ответа на команду.
        self._pending = []

    def call(self, method, **params):
        """Выполняет команду и возвращает её результат."""
        self._next_id += 1
        request = {"id": self._next_id, "method": method, "params": params}

        self._process.stdin.write(json.dumps(request, ensure_ascii=False) + "\n")
        self._process.stdin.flush()

        while True:
            answer = self._read()

            if "event" in answer:
                self._pending.append(answer)
            elif answer.get("id") == self._next_id:
                if answer["ok"]:
                    return answer["result"]
                raise BotError(answer["error"])

    def events(self):
        """Бесконечный поток событий."""
        while True:
            while self._pending:
                yield self._pending.pop(0)

            answer = self._read()
            if "event" in answer:
                yield answer

    def close(self):
        """Закрывает ввод: движок завершается сам."""
        self._process.stdin.close()
        self._process.wait()

    def _read(self):
        line = self._process.stdout.readline()

        if not line:
            raise SystemExit("движок gasapp-bot завершился")

        return json.loads(line)
