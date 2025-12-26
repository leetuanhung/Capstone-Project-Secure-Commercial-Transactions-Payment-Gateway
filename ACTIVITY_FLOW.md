# Sơ đồ luồng hoạt động (tổng quan)

Nếu bạn dùng extension kiểu **Mermaid Preview** (mở trực tiếp file để render), hãy mở các file `.mmd` (chỉ chứa Mermaid) để tránh lỗi lấy cả Markdown header làm Mermaid code:

- [diagrams/activity_overview.mmd](diagrams/activity_overview.mmd)
- [diagrams/payment_gateway_flow.mmd](diagrams/payment_gateway_flow.mmd)

```mermaid
flowchart LR
  %% Tổng quan toàn bộ hệ thống: User/Auth -> Order -> Payment (Fraud/OTP) -> Stripe/Webhook -> DB/Logs

  subgraph Actors["Tác nhân"]
    U["Người dùng"]
    ADM["Admin/Operator (tuỳ chọn)"]
  end

  subgraph FE["Frontend"]
    UI["Web UI (templates)"]
  end

  subgraph BE["Backend (FastAPI)"]
    GW["API Gateway / Router"]

    subgraph MW["Middleware / Security"]
      M1["Auth (JWT/OAuth2)"]
      M2["CSRF / CORS"]
      M3["Rate limiter"]
      M4["HMAC verifier (webhook)"]
      M5["Request ID + Logging"]
    end

    subgraph SVC["Services"]
      US["User service (Register/Login/Profile)"]
      OS["Order service (Cart/Order CRUD)"]
      PS["Payment service (Init/Confirm/Status)"]
      OTP["OTP service (Request/Verify)"]
      WH["Webhook handler (Stripe events)"]
    end

    subgraph SEC["Crypto/Fraud"]
      ENC["Encryption / E2E crypto"]
      FD["Fraud detection\n(ML/rules)"]
      AUD["PCI auditor (tuỳ chọn)"]
    end
  end

  subgraph EXT["Hệ thống ngoài"]
    STR["Stripe"]
    MAIL["Email/SMS Provider (OTP)"]
  end

  subgraph DATA["Lưu trữ"]
    DB["Database (users/orders/payments)"]
    LOGS["Logs/Monitoring"]
  end

  %% Truy cập hệ thống
  U --> UI --> GW
  ADM --> GW

  %% Lớp bảo vệ chung
  GW --> M2 --> M3 --> M5

  %% Auth/User
  M5 --> M1 --> US --> DB

  %% Order
  M5 --> OS --> DB

  %% Payment (kèm crypto + fraud + otp)
  M5 --> PS
  PS --> ENC
  PS --> FD
  FD --> DEC{"Rủi ro cao?"}
  DEC -->|"Có"| OTP --> MAIL
  OTP -->|"OTP hợp lệ"| PS
  DEC -->|"Không"| PS

  %% Stripe + webhook
  PS --> STR
  STR -->|"Webhook events"| WH --> M4 --> PS

  %% Persist + feedback
  PS --> DB
  DB --> UI

  %% Audit/observability
  M5 --> LOGS
  PS --> LOGS
  WH --> LOGS
  AUD --> DB

```

# Sơ đồ luồng hoạt động (Payment Gateway)

```mermaid
flowchart TD
  %% Luồng tổng quát: Checkout -> Tạo order/payment -> Fraud check -> OTP (nếu cần) -> Stripe -> Webhook -> Cập nhật trạng thái

  subgraph U["Người dùng"]
    U1["Chọn sản phẩm / Xem giỏ hàng"] --> U2["Checkout"]
    U2 --> U3["Nhập thông tin thanh toán"]
    U3 --> U4["Xác nhận thanh toán"]
  end

  subgraph FE["Frontend (templates)"]
    FE1["checkout.html"]
    FE2["otp_modal.html (nếu cần)"]
    FE3["success.html / error.html"]
  end

  subgraph API["Backend API (FastAPI)"]
    A1["POST /orders (tạo đơn hàng)"]
    A2["POST /payments (khởi tạo thanh toán)"]
    A3["POST /otp/request (gửi OTP)"]
    A4["POST /otp/verify (xác minh OTP)"]
    A5["POST /webhooks/stripe (nhận webhook)"]
  end

  subgraph SEC["Security Layer"]
    S1["Mã hoá/E2E encryption (payload nhạy cảm)"]
    S2["Fraud detection (ML/rule)"]
    S3["Rate limit / CSRF / HMAC verify"]
  end

  subgraph PAY["Payment Service"]
    P1["Tạo PaymentIntent / Charge"]
    P2["Cập nhật trạng thái Payment"]
  end

  subgraph PSP["Stripe"]
    ST1["Xử lý thanh toán"]
    ST2["Gửi webhook (succeeded/failed/...) "]
  end

  subgraph DB["Database"]
    D1["Lưu Order"]
    D2["Lưu Payment + trạng thái"]
  end

  %% UI -> FE -> API
  U2 --> FE1
  U4 -->|"Submit"| A1

  %% Tạo order
  A1 --> S3
  S3 --> S1
  S1 --> D1
  D1 --> A2

  %% Khởi tạo payment + fraud check
  A2 --> S2
  S2 --> DEC1{"Rủi ro cao?"}

  %% Nếu rủi ro cao: OTP
  DEC1 -->|"Có"| A3
  A3 --> FE2
  FE2 -->|"Nhập OTP"| A4
  A4 --> DEC2{"OTP hợp lệ?"}
  DEC2 -->|"Không"| FE3
  DEC2 -->|"Có"| P1

  %% Nếu rủi ro thấp: đi thẳng PSP
  DEC1 -->|"Không"| P1

  %% PSP
  P1 --> ST1
  ST1 -->|"Trả kết quả sync/redirect"| P2
  P2 --> D2

  %% Webhook async
  ST1 --> ST2
  ST2 --> A5
  A5 --> S3
  S3 --> P2
  P2 --> D2

  %% Kết quả cho user
  D2 -->|"Trạng thái cuối"| FE3

```

Gợi ý: nếu bạn muốn mình vẽ **luồng cụ thể hơn** (ví dụ: chỉ OTP flow, hoặc chỉ webhook flow), nói giúp 1 câu: bạn muốn sơ đồ cho phần nào (Checkout/OTP/Webhook/Auth)?
