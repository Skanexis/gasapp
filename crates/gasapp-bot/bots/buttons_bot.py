# SPDX-License-Identifier: Apache-2.0
"""Бот с кнопками: спрашивает и реагирует на нажатие.

    python buttons_bot.py ./mybot

На любое сообщение бот отвечает вопросом с двумя кнопками. Нажатие
приходит событием `callback` с данными кнопки.

Движок принимает нажатие, только если бот сам предложил кнопку с такими
данными под этим сообщением: `data` в событии — всегда одно из тех
значений, что бот отправил.
"""

import sys

from gasapp import Bot, BotError

ANSWERS = {"yes": "Записал: да.", "no": "Записал: нет."}


def ask(bot, who):
    bot.call(
        "sendMessage",
        to=who,
        text="Нравится GasApp?",
        buttons=[
            [{"text": "Да", "data": "yes"}, {"text": "Нет", "data": "no"}],
            [{"text": "Исходный код", "url": "https://example.org/source"}],
        ],
    )


def main():
    bot = Bot(sys.argv[1])

    for event in bot.events():
        who = event.get("from")
        if not who:
            continue

        try:
            if event["event"] == "message":
                ask(bot, who)
            elif event["event"] == "callback":
                # Кнопки под вопросом больше не нужны — убираем.
                bot.call("setButtons", to=who, message_id=event["message_id"], buttons=[])
                bot.call("sendMessage", to=who, text=ANSWERS[event["data"]])
        except BotError as error:
            if error.code == "peer_unconfirmed":
                # Ключ собеседника не подтверждён: верим серверу и
                # спрашиваем ещё раз (см. docs/bots.md, `trustContact`).
                bot.call("trustContact", username=who)
                ask(bot, who)
            else:
                print("не вышло:", error.code, file=sys.stderr)


if __name__ == "__main__":
    main()
