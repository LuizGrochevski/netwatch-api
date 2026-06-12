# 🛡️ Netwatch API

API REST de scanning de rede com autenticação JWT, construída com **FastAPI** e **Python**.

Desenvolvida para rodar em ambientes Linux/Android (Termux), combina segurança ofensiva com desenvolvimento backend seguro.

---

## 🚀 Funcionalidades

- 🔐 Autenticação com JWT (registro, login, token)
- 🔍 Port scanning de hosts e IPs
- 🗄️ Histórico de scans por usuário (SQLite)
- 📋 Consulta de scan por ID
- 📖 Documentação automática via Swagger

---

## 🛠️ Tecnologias

| Camada | Tecnologia |
|---|---|
| Framework | FastAPI |
| Servidor | Uvicorn |
| Autenticação | JWT (python-jose) + bcrypt |
| Banco de dados | SQLite |
| Linguagem | Python 3.13 |

---

## ⚙️ Instalação

```bash
git clone https://github.com/LuizGrochevski/netwatch-api
cd netwatch-api
python -m venv venv && source venv/bin/activate
pip install fastapi uvicorn python-jose passlib bcrypt python-dotenv python-multipart
```

Crie o `.env`:
```env
SECRET_KEY=sua_chave_secreta
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

Suba o servidor:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Acesse a documentação: `http://localhost:8000/docs`

---

## 📡 Endpoints

### Auth
| Método | Rota | Descrição |
|---|---|---|
| POST | `/auth/register` | Cria novo usuário |
| POST | `/auth/login` | Retorna token JWT |

### Scans
| Método | Rota | Descrição |
|---|---|---|
| POST | `/scan` | Executa scan em targets |
| GET | `/scan/{id}` | Resultado de um scan |
| GET | `/history` | Histórico do usuário |

---

## 🔒 Autenticação

Todos os endpoints de scan exigem token JWT no header:
```
Authorization: Bearer <token>
```

---

## 💡 Exemplo de uso

```bash
# Registrar
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "luiz", "password": "senha123"}'

# Login
curl -X POST http://localhost:8000/auth/login \
  -d "username=luiz&password=senha123"

# Scan
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["google.com", "github.com"]}'
```

---

## 📁 Estrutura

```
netwatch-api/
├── app/
│   ├── main.py       # Entrypoint
│   ├── routes.py     # Endpoints
│   ├── auth.py       # JWT e bcrypt
│   ├── database.py   # SQLite
│   └── models.py     # Schemas Pydantic
├── .env
└── README.md
```

---

## 👨‍💻 Autor

**Luiz Felipe Grochevski** — [LinkedIn](https://www.linkedin.com/in/luiz-felipe-grochevski) | [GitHub](https://github.com/LuizGrochevski)

ano README.md

# 🛡️ API Netwatch

API REST per la scansione di rete con autenticazione JWT, realizzata con **FastAPI** e **Python**.

Sviluppata per funzionare in ambienti Linux/Android (Termux), combina sicurezza offensiva con uno sviluppo backend sicuro.

---

## 🚀 Funzionalità

- 🔐 Autenticazione con JWT (registrazione, login, token)
- 🔍 Scansione delle porte di host e IP
- 🗄️ Cronologia delle scansioni per utente (SQLite)
- 📋 Query di scansione per ID
- 📖 Documentazione automatica tramite Swagger

---

## 🛠️ Tecnologie

| Livello | Tecnologia |

|---|---|

| Framework | FastAPI |

| Server | Uvicorn |

| Autenticazione | JWT (python-jose) + bcrypt |

| Database | SQLite |

| Linguaggio | Python 3.13 |


---

## ⚙️ Installazione

```bash
git clone https://github.com/LuizGrochevski/netwatch-api
cd netwatch-api
python -m venv venv && source venv/bin/activate
pip install fastapi uvicorn python-jose passlib bcrypt python-dotenv python-multipart
```

Crea il file `.env`:

```env
SECRET_KEY=la_tua_chiave_segreta
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

Avvia il server:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Accedi alla documentazione: `http://localhost:8000/docs`

---

## 📡 Endpoint

### Autenticazione
| Metodo | Percorso | Descrizione |

|---|---|---|

| POST | `/auth/register` | Crea un nuovo utente |

| POST | `/auth/login` | Restituisce un token JWT |

### Scansioni
| Metodo | Percorso | Descrizione |

|---|---|---|

| POST | `/scan` | Esegue una scansione sui target |

| GET | `/scan/{id}` | Risultato della scansione |

| GET | `/history` | Cronologia utente |

---

## 🔒 Autenticazione

Tutti gli endpoint di scansione richiedono un token JWT nell'intestazione:
```
Authorization: Bearer <token>
```

---

## 💡 Esempio di utilizzo

```bash
# Registrazione
curl -X POST http://localhost:8000/auth/register \

-H "Content-Type: application/json" \

-d '{"username": "luiz", "password": "senha123"}'

# Accesso
curl -X POST http://localhost:8000/auth/login \

-d "username=luiz&password=password123"

# Scansione
curl -X POST http://localhost:8000/scan \

-H "Authorization: Bearer <token>" \

-H "Content-Type: application/json" \

-d '{"targets": ["google.com", "github.com"]}'
```

---

## 📁 Struttura

```
netwatch-api/
├── app/
│ ├── main.py # Punto di ingresso
│ ├── routes.py # Endpoint
│ ├── auth.py # JWT e bcrypt
│ ├── database.py # SQLite
│ └── models.py # Schemi Pydantic
├── .env
└── README.md
```

---

## 👨‍💻 Autore

**Luiz Felipe Grochevski** — [LinkedIn](https://www.linkedin.com/in/luiz-felipe-grochevski) | [GitHub](https://github.com/LuizGrochevski)

