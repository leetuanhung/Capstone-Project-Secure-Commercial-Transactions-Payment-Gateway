# NT219.Q11.ATTN
Capstone Project — Secure Commercial Transactions &amp; Payment Gateway




```
NT219_Secure_Payment_Project/
├── 📂 backend/
│   ├── 📂 gateway/                          # 🚪 API GATEWAY - Cổng bảo mật tập trung
│   │   ├── main.py                          # 🎯 Khởi tạo FastAPI, routing chính
│   │   ├── 📂 middleware/                   # 🛡️ Lớp bảo mật middleware
│   │   │   ├── auth.py                      # 🔐 Xác thực JWT + OAuth2 token
│   │   │   ├── rate_limiter.py              # ⏱️ Giới hạn request theo IP/user
│   │   │   ├── hmac_verifier.py             # 🔑 Xác thực chữ ký HMAC request
│   │   │   ├── cors.py                      # 🌐 CORS security headers
│   │   │   └── request_id.py                # 🆔 Request tracing với UUID
│   │   └── 📂 utils/
│   │       ├── http_client.py               # 🌐 Async HTTP client
│   │       └── circuit_breaker.py           # ⚡ Circuit breaker cho service calls
│   │
│   ├── 📂 services/                         # 🏢 KIẾN TRÚC MICROSERVICES
│   │   ├── 📂 user_service/                 # 👥 SERVICE QUẢN LÝ NGƯỜI DÙNG
│   │   │   ├── main.py                      # 🎯 API user management
│   │   │   ├── auth.py                      # 🔑 MFA, password policies
│   │   │   └── device_fingerprinting.py     # 📱 Device binding & attestation
│   │   │
│   │   ├── 📂 order_service/                # 🛒 SERVICE QUẢN LÝ ĐƠN HÀNG
│   │   │   ├── main.py                      # 🎯 API orders & carts
│   │   │   ├── inventory.py                 # 📦 Quản lý tồn kho real-time
│   │   │   └── cart.py                      # 🛒 Giỏ hàng với expiry
│   │   │
│   │   └── 📂 payment_service/              # 💳 CORE PAYMENT ENGINE - QUAN TRỌNG
│   │       ├── main.py                      # 🎯 Payment API endpoints
│   │       ├── stripe_client.py             # 🔗 Stripe wrapper với retry logic
│   │       ├── 📂 security/                 # 🛡️ PAYMENT SECURITY CORE
│   │       │   ├── tokenization.py          # 🎫 Card tokenization (PCI DSS)
│   │       │   ├── hsm_client.py            # 🔒 AWS KMS/CloudHSM integration
│   │       │   ├── fraud_detection.py       # 🤖 ML fraud scoring + rules
│   │       │   ├── pci_auditor.py           # 📋 PCI-DSS compliance checks
│   │       │   ├── three_d_secure.py        # 🔐 3D Secure flows (PSD2 SCA)
│   │       │   └── encryption.py            # 🗂️ Field-level encryption
│   │       ├── 📂 webhooks/                 # 📨 Xử lý webhook từ PSP
│   │       │   ├── handler.py               # 🎯 Webhook event handler
│   │       │   └── signature_verifier.py    # ✍️ Xác thực webhook signature
│   │       ├── reconciliation.py            # 💰 Settlement & reconciliation
│   │       └── receipt_signing.py           # 📄 Digital receipts với HSM signing
│   │
│   ├── 📂 core/                             # ⚙️ CORE MODULES - Shared components
│   │   ├── config.py                        # 🔧 Environment configuration
│   │   ├── database.py                      # 🗄️ PostgreSQL + connection pool
│   │   ├── security.py                      # 🔐 JWT, crypto, key management
│   │   └── cache.py                         # 🚀 Redis client cho caching
│   │
│   ├── 📂 models/                           # 🗃️ DATABASE MODELS - SQLAlchemy
│   │   ├── user.py                          # 👤 User model với roles
│   │   ├── order.py                         # 📋 Order model với status tracking
│   │   ├── transaction.py                   # 💰 Transaction model
│   │   ├── fraud_attempt.py                 # 🚨 Fraud tracking & analytics
│   │   └── audit_log.py                     # 📝 Immutable audit trail
│   │
│   ├── 📂 schemas/                          # 📊 API SCHEMAS - Pydantic
│   │   ├── user.py                          # 📨 User request/response schemas
│   │   ├── order.py                         # 📦 Order schemas
│   │   ├── payment.py                       # 💳 Payment schemas
│   │   └── security.py                      # 🛡️ Security schemas
│   │
│   ├── 📂 crud/                             # 🛠️ DATABASE OPERATIONS
│   │   ├── user.py                          # 👤 User CRUD operations
│   │   ├── order.py                         # 📋 Order CRUD operations
│   │   ├── transaction.py                   # 💰 Transaction CRUD
│   │   └── audit.py                         # 📝 Audit log CRUD
│   │
│   ├── 📂 monitoring/                       # 📈 OBSERVABILITY & MONITORING
│   │   ├── metrics.py                       # 📊 Prometheus metrics collection
│   │   ├── alerts.py                        # 🚨 Security alerts & notifications
│   │   ├── audit_logger.py                  # 📝 Structured audit logging
│   │   └── performance.py                   # ⚡ Performance monitoring
│   │
│   ├── 📂 tests/                            # 🧪 TESTING SUITE
│   │   ├── unit/                            # 🧩 Unit tests
│   │   │   ├── test_payment_security.py     # 🛡️ Payment security tests
│   │   │   ├── test_fraud_detection.py      # 🤖 Fraud detection tests
│   │   │   └── test_tokenization.py         # 🎫 Tokenization tests
│   │   ├── integration/                     # 🔗 Integration tests
│   │   │   ├── test_payment_flow.py         # 💳 End-to-end payment tests
│   │   │   └── test_webhooks.py             # 📨 Webhook integration tests
│   │   └── security/                        # 🔒 Security penetration tests
│   │       ├── test_jwt_vulnerabilities.py  # 🎯 JWT security tests
│   │       └── test_rate_limit_bypass.py    # ⏱️ Rate limiting bypass tests
│   │
│   ├── 📂 migrations/                       # 🗃️ DATABASE MIGRATIONS
│   │   └── versions/                        # 📈 Alembic migration versions
│   │
│   ├── 📂 scripts/                          # 🛠️ DEPLOYMENT & UTILITY SCRIPTS
│   │   ├── deploy.sh                        # 🚀 Deployment script
│   │   ├── key_rotation.py                  # 🔑 Automated key rotation
│   │   └── pci_scan.py                      # 📋 PCI compliance scanner
│   │
│   ├── requirements.txt                     # 📦 Python dependencies
│   ├── Dockerfile                           # 🐳 Container configuration
│   └── docker-compose.yml                   # 🏗️ Multi-container setup
│
├── 📂 frontend/                             # 🎨 FRONTEND APPLICATION
│   ├── 📂 templates/                        # 🖼️ HTML Templates
│   │   ├── login.html                       # 🔐 Login page
│   │   ├── register.html                    # 📝 Registration page
│   │   ├── welcome.html                     # 🏠 Welcome dashboard
│   │   ├── store.html                       # 🏪 Product store
│   │   ├── cart.html                        # 🛒 Shopping cart
│   │   └── checkout.html                    # 💳 Checkout với hosted fields
│   ├── static/                              # 🎨 CSS, JS, Images
│   │   ├── css/
│   │   ├── js/
│   │   └── images/
│   └── main.py                              # 🎯 Frontend server
│
├── 📂 infrastructure/                       # 🏗️ INFRASTRUCTURE AS CODE
│   ├── kubernetes/                          # ☸️ K8s manifests
│   │   ├── deployment.yml                   # 🚀 Service deployments
│   │   ├── service.yml                      # 🌐 Service definitions
│   │   ├── ingress.yml                      # 🚪 Ingress configuration
│   │   └── hsm-config.yml                   # 🔒 HSM configuration
│   ├── terraform/                           # 🏗️ Terraform configurations
│   │   ├── main.tf                          # 🎯 Main infrastructure
│   │   ├── variables.tf                     # 📝 Environment variables
│   │   └── outputs.tf                       # 📤 Output configurations
│   └── monitoring/                          # 📊 Monitoring stack
│       ├── prometheus.yml                   # 📈 Prometheus config
│       └── grafana-dashboards/              # 📊 Grafana dashboards
│
├── 📂 docs/                                 # 📚 DOCUMENTATION
│   ├── architecture.md                      # 🏗️ System architecture
│   ├── api.md                               # 🌐 API documentation
│   ├── security.md                          # 🛡️ Security implementation
│   ├── deployment.md                        # 🚀 Deployment guide
│   └── pci_compliance.md                    # 📋 PCI compliance checklist
│
├── .env.example                             # 🔧 Environment template
├── .gitignore                               # 🙈 Git ignore rules
├── README.md                                # 📖 Project documentation
└── Makefile                                 # 🛠️ Development utilities

```
python -m uvicorn backend.main:app --reload

# tao certificate và key
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

uvicorn backend.main:app --ssl-keyfile="backend/ec-private-key.pem" --ssl-certfile="backend/certificate.crt"

echo 127.0.0.1 secureshop.kesug.com >> C:\Windows\System32\drivers\etc\hosts

type C:\Windows\System32\drivers\etc\hosts

https://secureshop.kesug.com:8000/
