# SPDX-License-Identifier: Apache-2.0
"""Эхо-бот: отвечает тем же текстом.

    python echo_bot.py ./mybot

Бот отвечает только тем, чей ключ подтверждён. Для незнакомых имён он
спрашивает сервер (`trustContact`) — то есть верит серверу на слово,
что это ключ этого имени. Для эхо-бота это разумно; для бота, который
сообщает что-то важное, — подумайте.
"""

import sys

from gasapp import Bot, BotError


def main():
    bot = Bot(sys.argv[1])
    print("бот запущен:", bot.call("getMe")["username"], file=sys.stderr)

    for event in bot.events():
        if event["event"] != "message" or not event.get("from"):
            continue

        sender = event["from"]

        try:
            bot.call("sendMessage", to=sender, text=event["text"])
        except BotError as error:
            if error.code != "peer_unconfirmed":
                print("не ответил:", error.code, file=sys.stderr)
                continue

            # Ключ собеседника не подтверждён — верим серверу и повторяем.
            try:
                bot.call("trustContact", username=sender)
                bot.call("sendMessage", to=sender, text=event["text"])
            except BotError as retry:
                print("не ответил:", retry.code, file=sys.stderr)


if __name__ == "__main__":
    main()
