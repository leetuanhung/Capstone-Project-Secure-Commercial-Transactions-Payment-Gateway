# Báo cáo: Điểm mạnh & Hạn chế (High-level)
## Secure Commercial Transactions & Payment Gateway (NT219 Capstone)

**Thời điểm tổng hợp**: December 25, 2025  
**Mục tiêu**: Đánh giá high-level về mức độ an toàn, độ tin cậy và mức sẵn sàng triển khai của hệ thống.

---

## 1) Executive summary

Hệ thống đã thể hiện tư duy **defense-in-depth** và mô hình bảo mật “nhiều lớp” cho giao dịch thanh toán: có các lớp kiểm soát truy cập/giảm lạm dụng, cơ chế xác thực bổ sung (OTP), phát hiện gian lận, xác thực webhook từ PSP và cơ chế log/audit. Ở mức đồ án, đây là một nền tảng tốt để minh họa các nguyên tắc bảo mật thực hành.

Tuy nhiên, để đạt mức “production-ready”, hệ thống vẫn còn một số rủi ro vận hành và an toàn thông tin (đặc biệt các nhánh **fail-open**, tính **idempotency** của webhook, và chuẩn hóa log để tránh lộ bí mật). Các hạn chế này không làm sai mục tiêu đồ án, nhưng cần được nêu rõ trong báo cáo và có kế hoạch cải tiến.

---

## 2) Điểm mạnh (Strengths)

- **Phòng thủ nhiều lớp (Defense-in-depth):** có nhiều lớp kiểm soát độc lập (giới hạn tốc độ, xác thực/tính toàn vẹn request, chống CSRF, truy vết request).
- **Bảo vệ tính toàn vẹn giao dịch:** có cơ chế chống sửa thông tin giao dịch phía client (anti-tamper) và chống gửi lặp (anti-replay) giúp giảm rủi ro gian lận dạng “request manipulation/replay”.
- **Xác thực bổ sung trước thanh toán:** OTP giúp giảm rủi ro từ việc chiếm tài khoản/phiên hoặc lạm dụng thanh toán tự động.
- **Phát hiện gian lận tích hợp trong luồng:** có framework fraud scoring/rules để chặn hoặc gắn cờ giao dịch rủi ro.
- **Giảm phạm vi PCI nhờ PSP:** luồng thanh toán dựa trên tokenization/PSP (Stripe) giúp giảm khả năng hệ thống trực tiếp xử lý/lưu thông tin thẻ (nếu triển khai frontend đúng chuẩn).
- **Webhook có xác thực nguồn gửi:** xác thực chữ ký webhook giúp hạn chế giả mạo sự kiện từ bên ngoài.
- **Khả năng audit/trace:** có phân loại log và mục tiêu audit/trace, hỗ trợ điều tra sự cố và chứng minh tuân thủ ở mức đồ án.

---

## 3) Hạn chế & rủi ro (Limitations)

- **Fail-open khi phụ thuộc hạ tầng gặp lỗi:** một số cơ chế an toàn có thể bị giảm hiệu lực khi Redis/fraud module lỗi (đổi bảo mật lấy khả năng “không bị down”).
- **Tính toàn vẹn request chưa bắt buộc cho mọi client:** nếu chữ ký/tầng integrity chỉ ở mức “tùy chọn”, giá trị bảo vệ phụ thuộc vào client có tuân thủ hay không.
- **Webhook cần idempotency rõ ràng:** PSP có thể retry hoặc gửi trùng sự kiện; nếu handler không idempotent sẽ có nguy cơ double-update.
- **Chưa tối ưu cho production (vận hành/hiệu năng):** cấu hình chạy dạng dev (auto-reload, mock state, thiếu chuẩn hóa hardening headers) làm giảm độ ổn định khi mở rộng.

### Các hạn chế “thực chiến” (chi phí – hạ tầng – vận hành)

- **Chi phí tuân thủ & kiểm toán (Compliance cost):** nếu triển khai thật sẽ phát sinh chi phí và quy trình (PCI-DSS/SAQ, quản lý vendor, chính sách lưu trữ log, kiểm thử bảo mật định kỳ, pentest, đào tạo). Đây là phần thường bị đánh giá thấp ở mức đồ án.
- **Chi phí hạ tầng cho bảo mật nâng cao:** các mục như HSM/KMS, key rotation, secret management, WAF/DDoS protection, log tập trung (SIEM), monitoring/alerting… tăng đáng kể chi phí vận hành và độ phức tạp triển khai.
- **Quản trị khóa & secret ở môi trường production:** quản lý vòng đời khóa (tạo/lưu/rotate/revoke), phân quyền truy cập secret, audit truy cập—nếu làm thủ công sẽ rủi ro cao; nếu dùng KMS/HSM thì cần hạ tầng và quy trình.
- **Độ sẵn sàng (Availability) phụ thuộc nhiều thành phần:** payment flow thường phụ thuộc DB/Redis/PSP/email provider; khi một thành phần degrade sẽ ảnh hưởng trực tiếp đến checkout. Thiết kế cần chiến lược graceful degradation có kiểm soát và SLO rõ ràng.
- **Khó khăn khi scale & đảm bảo nhất quán:** khi chạy nhiều instance, các vấn đề race-condition, idempotency, consistency của trạng thái đơn hàng/thanh toán/webhook trở nên quan trọng và khó hơn nhiều so với single-instance.
- **Quan sát hệ thống & phản ứng sự cố (Observability/Incident response):** để vận hành thật cần metric/tracing, cảnh báo, playbook xử lý sự cố, khả năng truy vết end-to-end, và quy trình xử lý chargeback/fraud. Nếu thiếu, hệ thống khó đạt chuẩn “production-ready” dù chức năng chạy được.
- **Chi phí gian lận & dữ liệu cho ML:** fraud detection “tốt” cần dữ liệu lịch sử, nhãn gian lận, pipeline huấn luyện, đánh giá drift, và human-in-the-loop. Ở mức đồ án thường chỉ mô phỏng, nhưng thực tế đây là hạng mục tốn thời gian/chi phí nhất.

---

## 4) Khuyến nghị cải tiến (High-level, theo ưu tiên)

| Ưu tiên | Mục tiêu | Kết quả kỳ vọng |
|---|---|---|
| P0 | Chuẩn hóa logging, không log bí mật | Giảm rò rỉ OTP/PII, dễ quan sát hệ thống |
| P0 | Idempotency webhook | Tránh double-update, tăng độ tin cậy đối soát |
| P1 | Chiến lược khi dependency lỗi (Redis/fraud) | Không “mất” lớp bảo vệ quan trọng khi hệ thống bất ổn |
| P1 | Ràng buộc integrity theo nhóm client/route | API-to-API có tính toàn vẹn bắt buộc, browser linh hoạt |
| P2 | Hardening & cấu hình production | Ổn định hơn khi deploy, giảm bề mặt tấn công web |

---

## 5) Kết luận

Ở mức high-level, hệ thống có nhiều điểm mạnh đáng ghi nhận về bảo mật và kiểm soát gian lận cho một đồ án payment gateway. Hạn chế hiện tại chủ yếu nằm ở “độ chín” vận hành (production hardening) và các góc cạnh an toàn khi hệ thống/đối tác retry hoặc dependency lỗi. Đây là các hạng mục phù hợp để đưa vào phần “future work / hướng phát triển” trong báo cáo.
