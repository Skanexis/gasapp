# SPDX-License-Identifier: Apache-2.0
"""Привратник закрытого канала: одобряет заявки по списку имён.

    python gatekeeper_bot.py ./mybot allowed.txt

`allowed.txt` — по одному имени на строку. Заявку от имени из списка бот
одобряет, от остальных — отклоняет. Подписчика, которого из списка
убрали, бот удаляет из канала при следующем запуске.

Бот должен быть администратором канала (см. docs/bots.md).

🔐 Одобрить — значит отдать ключ чтения канала. Имя заявителя бот знает
со слов сервера (`known_contact: false`): сервер, который лжёт, может
выдать чужую заявку за заявку человека из списка. Если это важно,
одобряйте только `known_contact: true` — флаг `--known-only`.
"""

import sys

from gasapp import Bot, BotError


def load_allowed(path):
    with open(path, encoding="utf-8") as file:
        return {line.strip().lstrip("@").lower() for line in file if line.strip()}


def managed_channels(bot):
    """Закрытые каналы, которые бот ведёт."""
    return [
        channel["channel_id"]
        for channel in bot.call("channels")
        if channel["closed"] and channel["role"] in ("admin", "owner")
    ]


def remove_strangers(bot, channel_id, allowed):
    """Удаляет подписчиков, которых больше нет в списке."""
    after = None

    while True:
        params = {"channel_id": channel_id}
        if after:
            params["after"] = after

        page = bot.call("subscribers", **params)
        if not page:
            return

        for member in page:
            if member["username"] and member["username"] not in allowed:
                try:
                    bot.call("removeSubscriber", channel_id=channel_id, account_id=member["account_id"])
                    print("удалён:", member["username"], file=sys.stderr)
                except BotError as error:
                    # Того, кто сам ведёт канал, так не удалить.
                    if error.code != "bad_request":
                        print("не удалён:", member["username"], error.code, file=sys.stderr)

        after = page[-1]["account_id"]


def main():
    known_only = "--known-only" in sys.argv
    arguments = [argument for argument in sys.argv[1:] if not argument.startswith("--")]
    bot = Bot(arguments[0])
    allowed = load_allowed(arguments[1])

    for channel_id in managed_channels(bot):
        remove_strangers(bot, channel_id, allowed)

    for event in bot.events():
        if event["event"] != "join_request":
            continue

        welcome = event["username"] in allowed and (event["known_contact"] or not known_only)
        method = "approveJoinRequest" if welcome else "declineJoinRequest"

        try:
            bot.call(method, channel_id=event["channel_id"], account_id=event["account_id"])
            print("одобрен:" if welcome else "отклонён:", event["username"], file=sys.stderr)
        except BotError as error:
            print("заявка не обработана:", event["username"], error.code, file=sys.stderr)


if __name__ == "__main__":
    main()
