# 🛡️ Netwatch API

![Python](https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-36%20passing-brightgreen?style=for-the-badge)

API REST de scanning de rede com autenticação JWT, construída com **FastAPI** e **Python**, integrada ao **[Sentinel-RS](https://github.com/LuizGrochevski/Sentinel-RS)** — scanner de alta performance em Rust.

Desenvolvida para rodar em ambientes Linux/Android (Termux), combina segurança ofensiva com desenvolvimento backend seguro.

---

## 🚀 Funcionalidades

- 🔐 Autenticação com JWT (registro, login, token)
- ✅ Validação de inputs com Pydantic
- 🔍 Port scanning TCP e UDP com ports customizáveis
- ⚡ Engine de scanning em Rust via Sentinel-RS
- 🗄️ Histórico de scans por usuário com paginação (SQLite)
- 📋 Consulta e exclusão de scans por ID
- 📊 Exportação de relatórios em JSON, CSV e Markdown
- 📖 Documentação automática via Swagger
- 🧪 36 testes automatizados com pytest e mocks
- 🐳 Containerização com Docker

---

## 🛠️ Tecnologias

| Camada | Tecnologia |
|---|---|
| Framework | FastAPI |
| Servidor | Uvicorn |
| Autenticação | JWT (python-jose) + bcrypt |
| Validação | Pydantic v2 |
| Banco de dados | SQLite |
| Scan Engine | [Sentinel-RS](https://github.com/LuizGrochevski/Sentinel-RS) (Rust/Tokio) |
| Testes | pytest + httpx + unittest.mock |
| Container | Docker + docker-compose |
| Linguagem | Python 3.13 |

---

## 🏗️ Arquitetura

```
POST /scan
    │
    ▼
netwatch-api (FastAPI)
    │  Validação de inputs (Pydantic)
    │  Autenticação JWT
    ▼
sentinel-rs (Rust/Tokio)
    ├── TCP scanning
    ├── UDP scanning
    ├── Service fingerprinting
    └── JSON report
    │
    ▼
SQLite (histórico paginado)
    │
    ▼
JSON / CSV / Markdown
```

---

## ⚙️ Instalação

### Pré-requisitos

- Python 3.13+
- [Sentinel-RS](https://github.com/LuizGrochevski/Sentinel-RS) compilado em `~/sentinel-rs/target/release/sentinel-rs`

### Setup

```bash
git clone https://github.com/LuizGrochevski/netwatch-api
cd netwatch-api
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
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

### Docker

```bash
docker-compose up --build
```

---

## 📡 Endpoints

### Auth
| Método | Rota | Descrição |
|---|---|---|
| POST | `/auth/register` | Cria novo usuário |
| POST | `/auth/login` | Retorna token JWT |
| GET | `/me` | Dados do usuário logado |

### Scans
| Método | Rota | Descrição |
|---|---|---|
| POST | `/scan` | Executa scan nos targets |
| GET | `/scan/{id}` | Resultado de um scan |
| DELETE | `/scan/{id}` | Remove um scan |
| GET | `/scan/{id}/report?format=csv` | Relatório em CSV |
| GET | `/scan/{id}/report?format=markdown` | Relatório em Markdown |
| GET | `/history?page=1&limit=10` | Histórico paginado |

---

## 🔒 Autenticação

Todos os endpoints de scan exigem token JWT no header:
```
Authorization: Bearer <token>
```

---

## ✅ Validações

| Campo | Regras |
|---|---|
| `username` | 3-32 chars, apenas letras/números/underscore |
| `password` | 6-72 chars |
| `targets` | máx. 10, IP ou hostname válido |
| `ports` | máx. 100, range 1-65535, suporta `80-90` |
| `protocol` | `tcp` ou `udp` |

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

# TCP Scan com ports customizadas
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.0.1", "google.com"], "ports": "22,80,443", "protocol": "tcp"}'

# UDP Scan
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.0.1"], "ports": "53,1900", "protocol": "udp"}'

# Histórico paginado
curl "http://localhost:8000/history?page=1&limit=10" \
  -H "Authorization: Bearer <token>"

# Deletar scan
curl -X DELETE http://localhost:8000/scan/1 \
  -H "Authorization: Bearer <token>"

# Relatório CSV
curl "http://localhost:8000/scan/1/report?format=csv" \
  -H "Authorization: Bearer <token>"
```

---

## 🧪 Testes

```bash
pytest tests/ -v
```

```
tests/test_auth.py          7 testes  — autenticação e JWT
tests/test_scan.py         15 testes  — scanning, relatórios, delete, paginação
tests/test_validation.py   14 testes  — validação de inputs
─────────────────────────────────────
Total: 36 passed
```

---

## 📁 Estrutura

```
netwatch-api/
├── app/
│   ├── main.py        # Entrypoint + lifespan
│   ├── routes.py      # Endpoints
│   ├── auth.py        # JWT e bcrypt
│   ├── database.py    # SQLite
│   ├── models.py      # Schemas Pydantic + validações
│   └── scanner.py     # Integração Sentinel-RS
├── tests/
│   ├── test_auth.py        # Testes de autenticação
│   ├── test_scan.py        # Testes de scanning
│   └── test_validation.py  # Testes de validação
├── .env
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 👨‍💻 Autor

**Luiz Felipe Grochevski** — [LinkedIn](https://www.linkedin.com/in/luiz-felipe-grochevski) | [GitHub](https://github.com/LuizGrochevski)

