// SPDX-License-Identifier: Apache-2.0
//
// Страница ссылки на канал: https://gasapp.eu/c/#ID.SECRET.KEY (открытый)
// или https://gasapp.eu/c/#join/ID.KEY.INVITE (закрытый — заявка).
//
// 🔐 Секрет канала — после «#»: браузер не отправляет эту часть на сервер,
// и сайт не узнаёт, какой канал открыли. Скрипт ничего не отправляет и не
// хранит: читает адрес, проверяет форму и собирает кнопку
// gasapp://channel/… для установленного приложения.
(function () {
  "use strict";

  var T = {
    en: {},
    ru: {
      title: "Канал в GasApp",
      lead: "Откройте ссылку в GasApp, чтобы вступить в канал. Записи зашифрованы: сервер их не читает.",
      open: "Открыть в GasApp", "no-app": "Ещё нет GasApp?",
      "as-small": "Загрузите в", "gp-small": "Доступно в",
      "android-hint": "Потом откройте ссылку ещё раз — или скопируйте её и вставьте в «Каналы → Вступить по ссылке».",
      "copy-label": "Скопировать ссылку", copied: "Ссылка скопирована",
      "bad-title": "Ссылка неполная", "bad-text": "Часть ссылки потерялась по дороге. Попросите прислать ссылку на канал ещё раз.",
      privacy: "Ключ канала стоит после «#» в адресе — на наш сервер он не попадает.", policy: "Политика конфиденциальности"
    },
    it: {
      title: "Un canale su GasApp",
      lead: "Apri questo link in GasApp per entrare nel canale. I post sono cifrati: il server non può leggerli.",
      open: "Apri in GasApp", "no-app": "Non hai ancora GasApp?",
      "as-small": "Scarica su", "gp-small": "Disponibile su",
      "android-hint": "Poi apri di nuovo il link, oppure copialo e incollalo in «Canali → Entra tramite link».",
      "copy-label": "Copia il link", copied: "Link copiato",
      "bad-title": "Il link è incompleto", "bad-text": "Una parte si è persa per strada. Chiedi di inviarti di nuovo il link del canale.",
      privacy: "La chiave del canale è dopo «#» nell’indirizzo: non arriva mai al nostro server.", policy: "Informativa sulla privacy"
    }
  };
  var lang = (navigator.language || "en").slice(0, 2).toLowerCase();
  var text = T[lang] || T.en;
  if (text !== T.en) {
    document.documentElement.lang = lang;
    Object.keys(text).forEach(function (id) {
      var node = document.getElementById(id);
      if (node) node.textContent = text[id];
    });
    if (lang === "ru") document.getElementById("policy").href = "/ru/privacy/";
  }

  var hash = location.hash.slice(1);
  // Формы ссылок ядра: открытый канал — id (32 hex), секрет и ключ
  // (Base32 по 52); закрытый — join/ id, ключ и приглашение (hex).
  var open = /^[0-9a-fA-F]{32}\.[A-Z2-7]{52}\.[A-Z2-7]{52}$/.exec(hash);
  var join = /^join\/([0-9a-fA-F]{32}\.[A-Z2-7]{52}\.[0-9a-fA-F]{2,128})$/.exec(hash);
  if (!open && !join) {
    document.getElementById("ok").classList.add("hidden");
    document.getElementById("bad").classList.remove("hidden");
    return;
  }

  document.getElementById("open-btn").href = open
    ? "gasapp://channel/" + hash
    : "gasapp://channel-join/" + join[1];

  var copy = document.getElementById("copy");
  copy.addEventListener("click", function () {
    var done = function () {
      document.getElementById("copy-label").textContent = text.copied || "Link copied";
      copy.classList.add("done");
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(location.href).then(done, function () {});
    }
  });
})();
