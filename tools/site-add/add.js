// SPDX-License-Identifier: Apache-2.0
//
// Страница ссылки на контакт: https://gasapp.eu/add/#KEY.PQ?name=…
//
// 🔐 Ключ — после «#»: браузер не отправляет эту часть на сервер, и сайт
// не узнаёт, чью ссылку открыли. Скрипт ничего не отправляет и не
// хранит: читает адрес, проверяет форму и собирает кнопку
// gasapp://contact/… для установленного приложения. Имя выводится
// только через textContent.
(function () {
  "use strict";

  var T = {
    en: {},
    ru: {
      title: "Пишите мне в GasApp",
      lead: "Откройте ссылку в GasApp, чтобы добавить меня. В ней мой ключ — посредник между нами не встанет.",
      open: "Открыть в GasApp", "no-app": "Ещё нет GasApp?",
      "as-small": "Загрузите в", "gp-small": "Доступно в",
      "android-hint": "Потом откройте ссылку ещё раз — или скопируйте её, нажмите в GasApp «Новый чат» и вставьте.",
      "copy-label": "Скопировать ссылку", copied: "Ссылка скопирована",
      "bad-title": "Ссылка неполная", "bad-text": "Часть ссылки потерялась по дороге. Попросите прислать ссылку GasApp ещё раз.",
      privacy: "Ключ стоит после «#» в адресе — на наш сервер он не попадает.", policy: "Политика конфиденциальности"
    },
    it: {
      title: "Scrivimi su GasApp",
      lead: "Apri questo link in GasApp per aggiungermi. Contiene la mia chiave: nessuno può mettersi in mezzo.",
      open: "Apri in GasApp", "no-app": "Non hai ancora GasApp?",
      "as-small": "Scarica su", "gp-small": "Disponibile su",
      "android-hint": "Poi apri di nuovo il link, oppure copialo, tocca «Nuova chat» in GasApp e incollalo.",
      "copy-label": "Copia il link", copied: "Link copiato",
      "bad-title": "Il link è incompleto", "bad-text": "Una parte si è persa per strada. Chiedi di inviarti di nuovo il link GasApp.",
      privacy: "La chiave è dopo «#» nell’indirizzo: non arriva mai al nostro server.", policy: "Informativa sulla privacy"
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
  // Форма ссылки ядра: два ключа Base32 по 52 знака и необязательное имя.
  var match = /^([A-Z2-7]{52}\.[A-Z2-7]{52})(\?name=([^\s#&]{1,400}))?$/.exec(hash);
  if (!match) {
    document.getElementById("ok").classList.add("hidden");
    document.getElementById("bad").classList.remove("hidden");
    return;
  }

  if (match[3]) {
    try {
      document.getElementById("name").textContent = decodeURIComponent(match[3]);
      document.getElementById("who").classList.remove("hidden");
    } catch (e) { /* имя не разобралось — просто не показываем */ }
  }

  document.getElementById("open-btn").href = "gasapp://contact/" + hash;

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
