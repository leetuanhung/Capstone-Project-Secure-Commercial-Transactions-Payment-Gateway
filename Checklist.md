# NT219 — Cryptography & Applications

## Checklist Hoàn Thiện Đề Tài *(Asset‑centric + System Architecture + Crypto Solution (03 lớp): Crypto / AuthN / AuthZ; Deployment Testing & Evaluation)*

> **Mục tiêu**: Xây dựng **đề xuất kiến trúc hệ thống** và **giải pháp mật mã 3 lớp** (Crypto / AuthN / AuthZ), sau đó **triển khai kiểm thử** trên **≥2 kịch bản triển khai** độc lập và **đánh giá định lượng** theo chỉ số đã đặt. *Không nhắc/động tới DFIR.*

---

## 0) Luồng làm việc tổng thể

**Bối cảnh & Tài sản → Đề xuất kiến trúc & Nguyên lý mật mã → Kế hoạch triển khai (Deployment Testing Plan) → Triển khai & Kiểm thử → Đo lường & Đánh giá (Evaluation) → Báo cáo.**

---

## 1) Asset‑Centric Context (AIM)

**1.1 Danh mục tài sản**

- **A1 Dữ liệu**: at‑rest, in‑transit, in‑process (độ nhạy, rủi ro).
- **A2 Bí mật & Khóa**: KEK/DEK, khóa chữ ký, token‑signing, seed TOTP, PSK (QR), v.v.
- **A3 Danh tính**: người dùng, dịch vụ, thiết bị (thuộc tính liên quan).
- **A4 Trạng thái & Chính sách**: session, JWT claims, RBAC/ABAC, ACL.
- **A5 Hạ tầng tin cậy**: CA, KMS/Vault, JWKS, attestation roots (nếu có).

**1.2 Ngữ cảnh & Ràng buộc**

- Kiến trúc triển khai (on‑prem/cloud/hybrid), phân vùng mạng, trust boundary, yêu cầu hiệu năng/độ trễ, ràng buộc pháp lý/quy chuẩn.

**1.3 Phân tích rủi ro & Mục tiêu bảo vệ (SMART)**

- **Rủi ro chính** (ngắn gọn): nghe lén, chỉnh sửa, replay, giả mạo, leo quyền, lộ/thu hồi khóa…
- **Giảm thiểu rủi ro tương ứng**: kênh bảo vệ, AEAD, PoP/mTLS‑bound, pin `alg`, deny‑by‑default, rotation…
- **Mục tiêu bảo vệ định lượng**: ví dụ *“0 byte plaintext rò rỉ”, “MFA success ≥ 99%; false‑accept = 0”, “rotate ≤ 10 phút; blast‑radius ≤ 24h”, “policy pass‑rate ≥ 95%”*.

---

## 2) System Architecture (Đề xuất)

**2.1 Sơ đồ kiến trúc (PNG/PDF)**: thể hiện boundary, thành phần, luồng dữ liệu, vị trí cưỡng chế/chính sách, nơi thi hành mật mã.

**2.2 Thành phần lõi & Quyết định kỹ thuật**

- **API Gateway**: rate‑limit, verify token, **PoP (DPoP hoặc mTLS‑bound)**; envelope encryption ở rìa nếu dùng.
- **IdP/IAM**: OIDC/OAuth 2.1; **WebAuthn/FIDO2** ưu tiên; fallback TOTP (không bypass recovery).
- **AuthZ**: PEP tại GW/service; **PDP OPA/Rego hoặc ACL kiểu Zanzibar**; deny‑by‑default; log quyết định có lý do.
- **KMS/Vault**: vòng đời khóa (gen/rotate/revoke/versioning/audit).
- **Observability**: logs có cấu trúc, metrics, trace; đồng bộ thời gian (chrony).
- **Nguyên tắc crypto**: AEAD cho truyền/lưu; **misuse‑resistant** khi phù hợp (GCM‑SIV/XChaCha20‑Poly1305) hoặc GCM với quản trị nonce chuẩn; chữ ký **Ed25519 hoặc ML-DSL** (tham số rõ); **PQC‑hybrid** *tùy chọn* nếu biện minh.

**2.3 Invariants (khẳng định cần được kiểm chứng)**

- **I1**: Không rò rỉ plaintext trên kênh bảo vệ.
- **I2**: Tampering (ciphertext/token) bị từ chối, có log giải thích.
- **I3**: Data (Authentication): Dữ liệu nguyên gốc, không bị chỉnh sửa
- **I4**: AuthN chống phishing; **token có ràng buộc sở hữu (PoP)** chống replay.
- **I5**: Quyết định AuthZ **giải thích được** từ log/chính sách.
- **I6**: Vận hành khóa **quan sát được**: rotate nhanh; blast‑radius giới hạn.
- **I7**: more on your project

---

## 3) Crypto Solution — 03 lớp

**3.1 Crypto (bảo vệ dữ liệu)**

- **Truyền**: TLS 1.3; ciphersuites thu gọn; tắt 0‑RTT cho giao dịch nhạy; (tùy) pinning.
- **Lưu trữ**: AEAD misuse‑resistant *hoặc* GCM + quản trị nonce; **envelope** tại gateway.
- **Chữ ký/Xác thực**: Ed25519/RSA‑PSS; tham số/hàm băm/label **tài liệu hóa**.
- **Quản trị khóa**: versioning, rotate, revoke, audit đầy đủ.

**3.2 AuthN (xác thực)**

- **Người dùng**: WebAuthn trước; TOTP dự phòng; khóa tài khoản, rate‑limit, chống bypass.
- **Dịch vụ**: mTLS **hoặc** SPIFFE/SPIRE (nếu dùng); trust store quản trị tập trung.
- **Quản lý Phiên**: cookie Secure+HttpOnly+SameSite; chống session fixation.

**3.3 AuthZ (cấp quyền / ủy quyền)**

- **Mô hình**: deny‑by‑default; least‑privilege; RBAC → ABAC (thuộc tính người dùng/thiết bị/ngữ cảnh).
- **Thi hành**: PEP@GW/service, PDP (OPA/Rego/Zanzibar); **log reason** mọi quyết định.
- **Token**: JWT pin `alg`; kiểm soát `kid`; TTL ngắn; refresh‑rotation & reuse‑detect; **DPoP/mTLS‑bound** cho PoP.

---

## 4) Deployment Testing (Kế hoạch triển khai)
>
> **Bắt buộc**: chọn **≥ 1** triển khai **khác nhau** cho cùng kiến trúc đề xuất. Mỗi triển khai phải có **Runbook** (lệnh, cấu hình, seed, script).

### D1. API‑Gateway + IdP + PDP (Linux/k8s)

- **Stack**: Envoy/Kong (PEP), Keycloak (OIDC + WebAuthn), OPA (PDP), Vault, JWKS.
- **Trọng tâm**: PoP = DPoP *hoặc* mTLS‑bound; policy ở OPA; envelope encrypt tại GW.

### D2. OpenStack (VM) — Zero‑Trust Tối giản

- **Stack**: NGINX/Envoy GW, Vault, Keycloak; phân vùng **private/dmz/mgmt**.
- **Trọng tâm**: mTLS east‑west; rotate qua Vault; thử gián đoạn thành phần.

### D3. WebAuthn + DPoP (tùy chọn)

- **Stack**: reverse proxy, IdP WebAuthn, middleware DPoP, pinning phía client.
- **Trọng tâm**: đăng nhập chống phishing; chống replay nhờ PoP; bootstrap QR→token.

> Có thể thay bằng IoT/Edge, PQC‑Hybrid… nếu nhóm có năng lực & biện minh hợp lệ.

---

## 5) Evaluation (Đánh giá định lượng theo invariants — *không DFIR*)

Liên hệ trực tiếp **I1–I5** và 3 lớp Crypto/AuthN/AuthZ.

**E‑Crypto**

- **E‑C1** Plaintext‑leakage: 0 byte giải mã được (kèm đối chứng kênh không bảo vệ).
- **E‑C2** Nonce discipline: tải cao không trùng lặp; lỗi giả lập → từ chối + log.
- **E‑C3** Integrity: sửa ciphertext/tag → bị chặn; chữ ký sai → verify fail.
- **E‑C3**: More for your project?

**E‑AuthN**

- **E‑N1** WebAuthn/TOTP: success ≥ 99%, false‑accept = 0; lockout đúng ngưỡng.
- **E‑N2** Service identity: chỉ dịch vụ hợp lệ truy cập; revoke/rotate có hiệu lực.

**E‑AuthZ**

- **E‑Z1** Ma trận role × resource × action (+ thuộc tính ABAC): pass‑rate **≥ 95%**; hành động không khai báo bị **deny 100%**.
- **E‑Z2** Token hardening: từ chối `alg=none`, `kid` injection, header confusion; log reason đầy đủ.

**E‑Cross**

- **E‑X1** Key rotation SLA: hoàn tất **≤ 10 phút**; key cũ bị từ chối trong **≤ 24h**.
- **E‑X2** Explainability: tái dựng quyết định AuthZ từ log/policy **100%** ca kiểm thử.

---

## 6) Chỉ số & Phương pháp đo

| Nhóm | Metric | Thu thập | Ngưỡng |
|---|---|---|---|
| Crypto | Plaintext leakage | kiểm tra giải mã/giám sát | **0 byte** |
| Crypto | AEAD error (bình thường) | counters/log | **0** |
| Crypto | Nonce reuse | bộ đếm/allocator | **0** |
| AuthN | Success / False‑accept | log IdP | **≥99% / 0** |
| AuthN | Lockout latency | diff log | **≤1s** |
| AuthZ | Policy pass‑rate | test matrix | **≥95%** |
| Token | Replay (PoP) | thử lại yêu cầu | **0** |
| Key | Rotation time | timeline | **≤10 phút** |
| Key | Blast‑radius | TTL/expire | **≤24h** |
| Obs | Explainability | tái dựng quyết định | **100%** |

---

## 7) Nộp sản phẩm cuối kỳ (Submission Pack)

1) **AIM.md** (Mục 1)  
2) **ARCH.pdf** + invariants (Mục 2)  
3) **CRYPTO_SOLUTION.md** (Mục 3)  
4) **DEPLOY/**: mỗi Dk có **Runbook.md**, configs, scripts  
5) **EVAL/**: thủ tục & số liệu cho các bài E‑*  
6) **POLICIES/**: Rego/ACL + test reports (JUnit/JSON)  
7) **EVIDENCE/**: logs, kết quả, (tùy) pcaps/ảnh màn hình  
8) **RESULTS.md**: bảng metric + kết luận (invariants đạt/chưa)  
9) **RUNBOOK.md**: hướng dẫn chạy từ máy sạch

---

## 8) Rubric chấm (100 điểm)

- **AIM (15)**: asset rõ (5), ràng buộc & mục tiêu SMART (10)  
- **Architecture (25)**: sơ đồ + invariants (15), rationale & quan sát được (10)  
- **Crypto Solution (15)**: 3 lớp gắn mục tiêu, không cố định thuật toán lỗi thời (15)  
- **Deployment Testing (20)**: ≥2 triển khai độc lập, runbook chuẩn, tái lập (20)  
- **Evaluation (15)**: bài đo bám invariants, metric định lượng, phân tích kết quả (15)  
- **Báo cáo (10)**: gói nộp đầy đủ, rõ ràng (10)

---

### Mẫu **Runbook** (mỗi Deployment)

```
Deployment ID & Name:
Mục đích & khác biệt so với kiến trúc tổng:
BOM (thành phần & phiên bản):
Trust boundaries & network:
Các bước cài đặt (lệnh, cấu hình):
Bootstrap secrets/keys & rotation:
Health checks & observability (metrics/logs):
Lỗi dự kiến & hành vi mong muốn:
```

### Mẫu **Evaluation Sheet**

```
Eval ID & Tên:
Liên hệ invariants:
Thủ tục đo (bước & công cụ):
Chỉ số & Ngưỡng:
Bằng chứng cần lưu:
Kết quả & Diễn giải:
Hướng cải tiến:
```