# Capstone Project — Secure Commercial Transactions & Payment Gateway

**Môn:** NT219 - Cryptography

**Tiêu đề đề tài:** Secure Commercial Transactions in Online Shopping and Payment Gateway — Thiết kế, triển khai và đánh giá an toàn cho giao dịch thương mại điện tử và hệ thống cổng thanh toán

---

## 1. Tóm tắt đề tài (Project Synopsis)

Đề tài hướng tới thiết kế một hệ thống **giao dịch thương mại điện tử an toàn** bao gồm: Frontend (web/mobile), API Gateway, Order & Payment orchestration, Payment Gateway tích hợp PSP/Acquirer, tokenization, reconciliation, settlement và reporting. Tập trung vào các khía cạnh mật mã và an ninh: bảo vệ dữ liệu thẻ (PAN), tokenization, PCI‑DSS scope reduction, TLS/mTLS, request signing, HSM/KMS cho key material, 3‑D Secure / SCA flow, chống gian lận (fraud detection), non‑repudiation (signed receipts), audit & non‑repudiation cho merchant disputes. Sinh viên sẽ xây dựng prototype có thể chạy trong môi trường lab, mô phỏng kịch bản tấn công (replay, manipulation, double‑spend, token theft, supply‑chain tampering), đo đạc hiệu năng (latency, TPS), và đề xuất chính sách vận hành & kỹ thuật để vận hành an toàn.

---

## 2. Mục tiêu học thuật & kỹ năng (Learning Objectives)

1. Hiểu đầy đủ luồng thanh toán hiện đại: Payment tokenization, PSP integration (gateway → acquirer → issuer), 3‑D Secure / PSD2 SCA flows, settlement & reconciliation.
2. Triển khai các biện pháp mật mã: envelope encryption, HSM‑backed signing, JWS/JWE for receipts/token, HMAC request signing, asymmetric signatures for non‑repudiation.
3. Thiết kế hệ thống giảm phạm vi PCI‑DSS (tokenization, client‑side encryption, PSP hosted fields), và xây dựng runbook để xử lý key compromise.
4. Đánh giá & thử nghiệm vectơ tấn công thực tế: token replay, man‑in‑the‑middle, API key leakage, race conditions (double spend), and supply chain compromise.
5. Thực hành triển khai công cụ chống gian lận: rule-based + ML scoring, device fingerprinting, chargeback analytics.

---

## 3. Tính cấp thiết & động lực (Relevance & Motivation)

* Giao dịch trực tuyến chiếm phần lớn doanh thu bán lẻ; sự cố trong cổng thanh toán gây tổn thất tài chính và pháp lý (chargebacks, fines).
* Quy định: PCI‑DSS, PSD2, GDPR yêu cầu kiểm soát dữ liệu thẻ và quyền người dùng; việc thiết kế hệ thống theo nguyên tắc minimal exposure là bắt buộc.
* Thực tế: nhiều vụ vi phạm xuất phát từ sai cấu hình (TLS, logging), quản lý key kém, hoặc SDK/third‑party bị tấn công — hiểu và thực nghiệm giảm thiểu rủi ro này là học thuật và thực tế.

---

## 4. Câu hỏi nghiên cứu & giả thuyết (RQ & Hypotheses)

**RQ1:** Thiết kế nào (client‑side tokenization + hosted fields vs server‑side tokenization vs hybrid) hiệu quả nhất để giảm PCI scope mà vẫn giữ trải nghiệm người dùng (latency) và khả năng mở rộng?

**RQ2:** Kết hợp HSM + signed receipts + per‑transaction nonces có ngăn chặn hiệu quả replay / tampering / merchant disputes không?

**RQ3:** Các biện pháp chống gian lận (behavioral ML + device binding + velocity checks) có thể giảm rate of successful fraud to acceptable levels while limiting false positives?

**Giả thuyết:** Client‑side tokenization + hosted payment fields (PSP) kết hợp short‑lived transaction tokens, HSM‑backed signing cho merchant receipts, và multi‑factor fraud scoring sẽ giảm signficantly both PCI scope and fraud outcomes; overhead latency can be mitigated by caching and asynchronous reconciliation.

---

## 5. Background (Tổng quan ngắn)

* **Payment flow basics:** card‑holder → merchant → payment gateway → acquirer → card network → issuer; tokenization replaces PAN with token; 3‑D Secure (EMV 3DS) adds step for payer authentication.
* **Standards & regs:** PCI‑DSS v4.0, PSD2 SCA, EMV 3DS2, GDPR data protection rules.
* **Cryptographic primitives:** TLS (mutual for S2S), HMAC for request signing (HMAC‑SHA256), JWS/JWE for receipts & tokens, asymmetric signatures (RSA/ECDSA) for non‑repudiation, HSM/KMS for key management, envelope encryption for data at rest.

---

## 6. Literature & industry references (hướng khảo sát)

* PCI‑DSS documentation and SAQ guidance (Hosted Payment Fields vs Full SAQ).
* EMV 3DS 2.x specifications and PSD2 SCA guidelines.
* Research papers and industry posts on tokenization, payment fraud ML, secure SDKs, and incidents (e.g., Magecart supply‑chain attacks).

> Yêu cầu: sinh viên trích dẫn tối thiểu 6 nguồn chính thức (PCI, EMV, PSD2) và 4 bài báo hoặc technical reports liên quan.

---

## 7. Hệ thống & thành phần (System Components)

### 7.1. Thành phần chính

* **Client apps / Browser:** Checkout page uses hosted fields or client SDK; obtains ephemeral payment token or nonce.
* **API Gateway:** TLS termination, JWT/OAuth validation, rate limiting, signed request verification.
* **Order Service:** creates order, reserves stock, computes amount.
* **Payment Orchestrator (Gateway):** receives payment token, interacts with PSP/Acquirer, handles 3DS redirect/checkbox flows, logs transaction events, persists signed receipts.
* **PSP / Acquirer (sandbox):** partner service (Stripe, Adyen, Braintree) used in test mode; supports hosted fields, tokenization, 3DS, webhooks.
* **KMS / HSM:** store keys used for signing receipts and decrypting wrapped keys; used for key wrapping/unwrapping and for signing settlement files.
* **Fraud Detection Engine:** rule engine + ML model to score transaction risk; triggers challenge or manual review.
* **Settlement & Reconciliation:** batch settlement, reconciliation with PSP reports, ledger for audit.
* **Audit & Monitoring:** immutable logs (signed), SIEM, alerting for anomalous patterns.

### 7.2. Supporting infra & resources

* Containerized microservices (Kubernetes), database (Postgres), message queue (Kafka/RabbitMQ), object storage for reports, TLS certs & OCSP, HSM (cloud HSM or SoftHSM for tests), PSP sandbox accounts, load testing tools.

---

## 8. Kịch bản triển khai thực tế & phân tích weakness (Deployment Scenarios & Weaknesses)

### 8.1. Small‑merchant / Embedded PSP (PoC)

* **Weaknesses:** using PSKs or static API keys in code, logging PANs, no HSM for signing, long‑lived tokens.
* **Consequences:** data breach, PCI fines.

### 8.2. High‑volume eCommerce (Scale/Global)

* **Weaknesses:** latency-sensitive connectors, caching of tokens, poor key rotation automation, inconsistent 3DS fallback policies across regions leading to fraud.
* **Consequences:** increased fraud, chargebacks, loss of revenue and reputation.

### 8.3. Mobile wallets & in‑app payments

* **Weaknesses:** insecure SDK integration, weak device binding, lacking attestation leading to token replay/abuse on rooted devices.
* **Consequences:** account takeover, fraudulent purchases.

### 8.4. Supply chain / Third‑party SDK risks

* **Weaknesses:** inclusion of compromised JS SDK (Magecart), CI pipeline compromise leading to malicious code signing.
* **Consequences:** mass skimming of PANs, silent exfiltration.

### 8.5. Chargeback & dispute handling weaknesses

* **Weaknesses:** lack of non‑repudiable signed receipts, poor logging and audit trails, missing reconciliation causing disputes.
* **Consequences:** high chargeback rates, revenue loss.

---

## 9. Methodology (Experimentation & PoC)

### 9.1. PoC scope

* Implement a minimal but realistic checkout: merchant frontend (hosted fields) → Order Service → Payment Orchestrator → PSP sandbox. Integrate HSM/SoftHSM for signing receipts and storing wrapping keys. Add Fraud Engine (simple rules + ML stub). Provide reconciliation worker.

### 9.2. Experiments

1. **PCI scope reduction comparison:** compare hosted fields vs direct PAN submission vs client‑side encryption in terms of PCI requirements, latency, and complexity.
2. **Token replay & nonce tests:** attempt to replay ephemeral tokens across sessions; verify binding to order & device.
3. **Signed receipts & non‑repudiation:** sign transaction receipts with HSM and examine how signatures enable dispute resolution.
4. **Fraud simulation:** run synthetic fraud patterns (card‑testing, velocity attacks, stolen token usage) and measure detection rate with rules vs ML.
5. **HSM compromise drill:** simulate HSM key compromise (rotate keys) and test incident response & re‑signing process for settlement files.
6. **Supply chain attack simulation:** insert malicious JS in dev environment (controlled) to test detection & CI/CD signing enforcement.

### 9.3. Measurements & logging

* Collect logs: transaction timelines, latency (checkout → settlement), fraud scores, false positives/negatives, chargeback simulations, key rotation time, HSM usage metrics.

---

## 10. Implementation & Tools

* **PSP sandbox:** Stripe test mode, Adyen sandbox, Braintree sandbox.
* **Hosted fields & SDKs:** Stripe Elements, Adyen Checkout, or self‑hosted iframe approach.
* **HSM/KMS:** AWS CloudHSM / AWS KMS (with CloudHSM), Azure Key Vault HSM, or SoftHSM for lab. Use PKCS#11 for integration.
* **3DS & SCA:** EMV 3DS flows via PSP or open source emulators.
* **Fraud tooling:** custom rule engine + simple ML model (scikit‑learn), device fingerprinting libs, Redis for rate limiting.
* **Monitoring & SIEM:** ELK/EFK, Prometheus, Grafana, audit logs signed with JWS.
* **Testing:** JMeter/wrk, Cypress for end‑to‑end, Burp/ZAP for security testing.

---

## 11. Evaluation Plan & Metrics

* **Security:** % successful replay attempts, % token misuse, time‑to‑detect compromise, ability to resolve disputes using signed receipts.
* **Fraud metrics:** true/false positive rate of fraud engine, reduction in fraudulent acceptance rate.
* **Performance:** checkout latency (TTF, median/p95/p99), TPS at payment orchestrator, HSM call latency and throughput.
* **Operational:** PCI scope (SAQ level), time to rotate keys & recover from key compromise, cost per 10k transactions.

---

## 12. Timeline & Milestones (12 tuần)

* **Tuần 1–2:** Requirement analysis, threat model, choose PSP sandbox, provision infra (k8s, SoftHSM).
* **Tuần 3–4:** Implement frontend checkout (hosted fields) + Order Service skeleton.
* **Tuần 5–6:** Implement Payment Orchestrator, integrate PSP sandbox, implement basic reconciliation & signed receipt flow using SoftHSM.
* **Tuần 7–8:** Add Fraud Engine (rule‑based + ML prototype), implement token binding & replay detection.
* **Tuần 9:** Run security experiments (replay, supply chain sim, double‑spend race), collect metrics.
* **Tuần 10:** Perform HSM compromise drill and key rotation tests; finalize incident response playbook.
* **Tuần 11:** Performance & scale testing; fine‑tune thresholds and ML model.
* **Tuần 12:** Final report, reproducible repo (Docker/Helm), demo video & presentation.

---

## 13. Deliverables

1. **Mid‑term:** architecture diagram, threat model, initial PoC (checkout → PSP sandbox).
2. **Final report:** methodology, experiments, results, mitigations, and runbooks (incident response, key rotation).
3. **Code repo:** frontend, order service, payment orchestrator, SoftHSM integration, fraud engine, reconciliation worker, test harness.
4. **Artifacts:** sample signed receipts, logs, CSVs of tests, demo video.
5. **Compliance checklist:** PCI‑DSS mapping and SAQ guidance for the chosen design.

---

## 14. Assessment & Rubric (gợi ý)

* Security design & threat modeling: 25%
* Implementation & reproducibility (working PoC): 25%
* Experimental rigor & analysis (fraud & security tests): 25%
* Documentation, runbooks & presentation: 25%

---

## 15. Risks, Limitations & Ethical Considerations

* **Payment data:** use PSP sandbox and test card numbers only; do not process real PANs in experiments.
* **Fraud experiments:** synthetic only; do not target real issuers or networks.
* **Key compromise drills:** avoid exposing real production keys; use isolated HSM/test keys.

---

## 16. Mitigations & Best Practices (summary recommendations)

* **Tokenization & hosted fields:** minimize PCI scope by using PSP hosted fields or client‑side tokenization.
* **HSM/KMS for keys:** use HSM for signing and key wrap; implement automated key rotation and limited access policies.
* **Per‑transaction nonces & signed receipts:** bind tokens to order & device; sign receipts with asymmetric keys for non‑repudiation.
* **mTLS & HMAC for internal APIs:** secure service‑to‑service calls with mTLS and request signing.
* **Fraud defense in depth:** combine velocity checks, device binding, 3DS for suspected transactions, and ML scoring with manual review paths.
* **Supply chain hardening:** lock down JS supply chain, use Subresource Integrity (SRI), sign CI artifacts, and monitor vendor updates.

---

## 17. Extensions & Future Work

* Integration with real HSM appliances and enterprise PCI‑compliant deployments.
* Explore PSD2 open banking flows & secure token exchange between merchants and banks.
* Research into PQC readiness for payment signatures and long‑term receipts.

---

## 18. Tools & Resources gợi ý

* PSP sandboxes: Stripe, Adyen, Braintree; HSMs: AWS CloudHSM / SoftHSM for lab; Hosted Fields SDKs; EMV 3DS docs; PCI‑DSS guides; Burp/ZAP; ELK/Prometheus; scikit‑learn for ML fraud model.

---

## 19. Appendix: Repository Structure (mẫu)

```
project-root/
  ├─ frontend/           # checkout page (hosted fields example), test scripts
  ├─ services/
  |   ├─ order/
  |   ├─ payment_orchestrator/
  |   ├─ reconciliation/
  |   └─ fraud_engine/
  ├─ infra/              # docker-compose / helm charts, SoftHSM configs
  ├─ docs/               # report, PCI mapping, runbooks
  └─ experiments/        # replay_tests, supply_chain_sim, hsm_compromise_drill, load tests
```

---