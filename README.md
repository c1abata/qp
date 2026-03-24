# 🚀 QuickPeek

**QuickPeek** è uno strumento Python leggero per il monitoraggio e l’analisi di sistema/rete, progettato per essere veloce, modulare e facilmente estendibile.

---

## ✨ Caratteristiche

* 📡 Monitoraggio rete
* 🔔 Sistema di alert (modulare)
* 📂 Architettura a moduli (`lib/`, `tasks/`)
* ⚙️ Configurazione tramite file (`config.ini`)
* 🧩 Estendibile con nuove funzionalità

---

## 📁 Struttura del progetto

```
quickpeek/
├── main.py
├── config.ini
├── lib/
│   ├── alert.py
│   ├── bluetooth_alert.py
│   └── ...
├── tasks/
│   └── ...
├── requirements.txt
└── README.md
```

---

## ⚙️ Installazione

### 1. Clona il repository

```bash
git clone git@github.com:c1abata/quickpeek.git
cd quickpeek
```

Oppure (HTTPS):

```bash
git clone https://github.com/c1abata/quickpeek.git
```

---

### 2. Crea ambiente virtuale

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### 3. Installa dipendenze

```bash
pip install -r requirements.txt
```

---

## ▶️ Utilizzo

```bash
python main.py
```

---

## ⚙️ Configurazione

Modifica il file:

```
config.ini
```

⚠️ **NON inserire credenziali sensibili nel repository pubblico**

Per configurazioni sensibili:

* usa variabili ambiente (`.env`)
* oppure file locali esclusi da `.gitignore`

---

## 🔐 Sicurezza

* `.env` escluso dal versionamento
* nessuna credenziale hardcoded
* supporto a configurazioni locali sicure

---

## 🔄 Workflow sviluppo

```bash
git pull
git add .
git commit -m "descrizione modifiche"
git push
```

---

## 🧪 Testing (consigliato)

```bash
python -m unittest
```

---

## 📦 Deploy (opzionale)

Può essere integrato con:

* systemd (Linux service)
* CI/CD pipeline (GitHub Actions / GitLab CI)

---

## 🤝 Contributi

Pull request benvenute!

1. Fork del repository
2. Crea un branch:

   ```bash
   git checkout -b feature-nome
   ```
3. Commit:

   ```bash
   git commit -m "aggiunta feature"
   ```
4. Push e PR

---

## 📄 Licenza

Aggiungere una licenza (es. MIT) per uso pubblico.

---

## 👤 Autore

* GitHub: https://github.com/c1abata

---

## 💡 Note

Questo progetto è pensato per:

* uso personale avanzato
* sperimentazione
* automazione di sistema

---

## ⭐ Supporto

Se il progetto ti è utile:

* ⭐ metti una stella su GitHub
* contribuisci al miglioramento
