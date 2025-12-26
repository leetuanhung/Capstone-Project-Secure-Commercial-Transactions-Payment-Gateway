# Middleware (chức năng, input, output)

## Thứ tự chạy (runtime)
Trong [backend/main.py](backend/main.py) middleware được add theo thứ tự:
1) CORS (`setup_cors` / `CORSMiddleware`)
2) `RequestIDMiddleware`
3) `RateLimitMiddleware`
4) `HMACVerifierMiddleware`
5) `CSRFMiddleware`

Starlette/FastAPI sẽ **chạy request theo thứ tự ngược lại** (outermost chạy trước):
- **Incoming**: CSRF → HMAC → RateLimit → RequestID → CORS → Router
- **Outgoing (unwind)**: Router → CORS → RequestID → RateLimit → HMAC → CSRF

Sơ đồ chi tiết: [diagrams/middleware_flow.mmd](diagrams/middleware_flow.mmd)

---

## 1) CSRFMiddleware
**Mục tiêu**: chống CSRF cho các request unsafe (POST/PUT/PATCH/DELETE) theo mô hình **double-submit cookie**.

**Khi nào áp dụng**:
- Safe methods: `GET/HEAD/OPTIONS` → không chặn, nhưng **đảm bảo có cookie `csrf_token` ở response**.
- Unsafe methods: `POST/PUT/PATCH/DELETE` → **bắt buộc** token gửi lên phải khớp cookie (trừ khi exempt).

**Exempt (bỏ qua CSRF)** (được cấu hình tại [backend/main.py](backend/main.py)):
- `exempt_paths`: `/webhook`, `/debug-webhook`, `/openapi.json`
- `exempt_prefixes`: `/docs`, `/redoc`, `/auth`, `/user_service`

**Input**:
- `request.method`, `request.url.path`
- Cookie: `csrf_token`
- Token submit (ưu tiên theo thứ tự):
  1) Header: `X-CSRF-Token` hoặc `X-XSRF-Token`
  2) JSON body: key `csrf_token` (Content-Type `application/json`)
  3) Form field: `csrf_token` (urlencoded/multipart)
- Header: `Accept` (để chọn HTML vs JSON khi trả lỗi)

**Output (Success)**:
- Cho request đi tiếp qua `call_next(request)`.
- Với `GET/HEAD/OPTIONS`: nếu thiếu cookie, middleware **set cookie `csrf_token`** vào response.

**Output (Failure)**:
- `403` + `Cache-Control: no-store`
- Nếu `Accept` chứa `text/html`: trả `HTMLResponse("CSRF validation failed")`
- Ngược lại: trả `JSONResponse({"detail": "CSRF validation failed"})`

**Side-effects**:
- Có thể **đọc body** để lấy token (JSON/form) nhưng Starlette cache body nên endpoint vẫn đọc được.

Files liên quan:
- [backend/middleware/csrf.py](backend/middleware/csrf.py)
- [backend/utils/csrf.py](backend/utils/csrf.py)

---

## 2) HMACVerifierMiddleware
**Mục tiêu**: chống giả mạo request (integrity/authenticity) cho request có ký HMAC.

**Input**:
- Header: `X-Signature` (HMAC-SHA256 của raw body)
- Raw body: `await request.body()`
- Env:
  - `GATEWAY_HMAC_SECRET` (default `gateway-secret-key`)
  - `ENFORCE_TLS=true|false`
- `request.url.scheme` để kiểm tra HTTPS khi bật ENFORCE_TLS

**Output (Success)**:
- Nếu **không có** `X-Signature`: cho qua (ví dụ trang login)
- Nếu có chữ ký và hợp lệ: cho qua `call_next(request)`

**Output (Failure)**:
- Nếu `ENFORCE_TLS=true` và có signature nhưng không phải HTTPS: `403` JSON `{"detail":"HMAC-signed requests must use HTTPS"}`
- Nếu signature có nhưng sai: `403` JSON `{"detail":"Invalid HMAC signature"}`

Files liên quan:
- [backend/middleware/hmac_verifier.py](backend/middleware/hmac_verifier.py)

---

## 3) RateLimitMiddleware
**Mục tiêu**: chống spam/DoS bằng giới hạn tần suất theo IP.

**Chính sách**:
- `RATE_LIMIT = 60` requests / `WINDOW = 60` giây / mỗi IP.

**Input**:
- `request.client.host` (IP)
- Redis (nếu kết nối được):
  - `REDIS_HOST`, `REDIS_PORT`, `REDIS_DB`

**Output (Success)**:
- Nếu chưa vượt giới hạn: `call_next(request)`

**Output (Failure)**:
- Nếu vượt giới hạn: `429` JSON `{"detail":"Too many requests. Try again later."}`

**Side-effects**:
- Ưu tiên Redis sliding-window bằng sorted set.
- Nếu Redis không khả dụng: fallback in-memory + có thể log security event `rate_limit_exceeded`.

Files liên quan:
- [backend/middleware/rate_limiter.py](backend/middleware/rate_limiter.py)

---

## 4) RequestIDMiddleware
**Mục tiêu**: tracing/log correlation cho mỗi request.

**Input**:
- Sinh `UUID` cho mỗi request
- Cookie `user_id` (nếu có) để set log context
- IP từ `request.client.host`

**Output**:
- Set `request.state.request_id`
- Thêm header response: `X-Request-ID: <uuid>`
- Luôn clear log context ở `finally`

Files liên quan:
- [backend/middleware/request_id.py](backend/middleware/request_id.py)
- [backend/utils/logger.py](backend/utils/logger.py)

---

## 5) CORS (CORSMiddleware)
**Mục tiêu**: cho phép frontend gọi API cross-origin theo danh sách origin được allow.

**Input**:
- Headers: `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers`
- Preflight: `OPTIONS` + `Origin` + `Access-Control-Request-Method`

**Output**:
- Với preflight: trả response luôn (kèm CORS headers)
- Với request thường: thêm CORS headers vào response

**Cấu hình** (xem [backend/middleware/cors.py](backend/middleware/cors.py)):
- `allow_origins`: `http://127.0.0.1:8000`, `http://localhost:8000`, `http://127.0.0.1:5173`
- `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]`

Files liên quan:
- [backend/middleware/cors.py](backend/middleware/cors.py)
