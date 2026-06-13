# 🛡️ Netwatch API

API REST de scanning de rede com autenticação JWT, 
construída com **FastAPI** e **Python**, integrada ao **[Sentinel-RS](https://github.com/LuizGrochevski/Sentinel-RS)** — scanner de alta performance em Rust.

Desenvolvida para rodar em ambientes Linux/Android 
(Termux), combina segurança ofensiva com desenvolvimento backend seguro.

---

## 🚀 Funcionalidades

- 🔐 Autenticação com JWT (registro, login, token)
- 🔍 Port scanning TCP e UDP com ports customizáveis
- ⚡ Engine de scanning em Rust via Sentinel-RS
- 🗄️ Histórico de scans por usuário (SQLite)
- 📋 Consulta de scan por ID
- 📊 Exportação de relatórios em JSON, CSV e Markdown
- 📖 Documentação automática via Swagger
- 🧪 13 testes automatizados com pytest
- 🐳 Containerização com Docker

---

## 🛠️ Tecnologias

| Camada | Tecnologia |
|---|---|
| Framework | FastAPI |
| Servidor | Uvicorn |
| Autenticação | JWT (python-jose) + bcrypt |
| Banco de dados | SQLite |
| Scan Engine | 
| [Sentinel-RS](https://github.com/LuizGrochevski/Sentinel-RS) (Rust/Tokio) |
| Testes | pytest + httpx |
| Container | Docker + docker-compose |
| Linguagem | Python 3.13 |

---

## 🏗️ Arquitetura

```
POST /scan
    │
    ▼
netwatch-api (FastAPI)
    │
    ▼
sentinel-rs (Rust/Tokio)
    ├── TCP scanning
    ├── UDP scanning
    ├── Service fingerprinting
    └── JSON report
    │
    ▼
SQLite (histórico)
    │
    ▼
JSON / CSV / Markdown
```

---

## ⚙️ Instalação

### Pré-requisitos

- Python 3.13+
- 
[Sentinel-RS](https://github.com/LuizGrochevski/Sentinel-RS) compilado em `~/sentinel-rs/target/release/sentinel-rs`

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
| GET | `/scan/{id}/report?format=csv` | Relatório em CSV 
| |
| GET | `/scan/{id}/report?format=markdown` | Relatório em 
| Markdown |
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

# TCP Scan com ports customizadas
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.0.1"], "ports": "22,80,443", 
"protocol": "tcp"}'

# UDP Scan
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.0.1"], "ports": "53,1900", 
"protocol": "udp"}'

# Relatório CSV
curl "http://localhost:8000/scan/1/report?format=csv" \
  -H "Authorization: Bearer <token>"

# Relatório Markdown
curl "http://localhost:8000/scan/1/report?format=markdown" 
\
  -H "Authorization: Bearer <token>"
```

---

## 🧪 Testes

```bash
pytest tests/ -v
```

```
tests/test_auth.py::test_register_success         PASSED
tests/test_auth.py::test_register_duplicate       PASSED
tests/test_auth.py::test_login_success            PASSED
tests/test_auth.py::test_login_wrong_password     PASSED
tests/test_auth.py::test_login_unknown_user       PASSED
tests/test_auth.py::test_get_me                   PASSED
tests/test_auth.py::test_get_me_unauthorized      PASSED
tests/test_scan.py::test_scan_unauthorized        PASSED
tests/test_scan.py::test_scan_success             PASSED
tests/test_scan.py::test_scan_result_structure    PASSED
tests/test_scan.py::test_get_scan_by_id           PASSED
tests/test_scan.py::test_get_scan_not_found       PASSED
tests/test_scan.py::test_history                  PASSED
======================== 13 passed 
========================
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
│   ├── models.py      # Schemas Pydantic
│   └── scanner.py     # Integração Sentinel-RS
├── tests/
│   ├── test_auth.py   # Testes de autenticação
│   └── test_scan.py   # Testes de scanning
├── .env
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 👨‍💻 Autor

**Luiz Felipe Grochevski** — 
[LinkedIn](https://www.linkedin.com/in/luiz-felipe-grochevski) | [GitHub](https://github.com/LuizGrochevski)

