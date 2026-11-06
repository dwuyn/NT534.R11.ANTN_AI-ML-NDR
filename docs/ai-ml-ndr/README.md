# NDR + AI/ML — Hồ sơ thiết kế và kế hoạch triển khai

> **Đồ án:** Network Detection and Response (NDR) với Zeek  
> **Yêu cầu bổ sung:** tích hợp AI/ML vào NDR  
> **Môn học:** An toàn mạng máy tính nâng cao (NT534)

Thư mục này là bộ tài liệu thiết kế cho việc bổ sung lớp AI/ML vào hệ thống NDR hiện có (Zeek + Suricata + Filebeat + Elasticsearch/Kibana + response automation), bám sát 6 kịch bản tấn công trong `ndr_with_zeek.pdf`.

## 1. Kết luận nhanh (TL;DR)

1. **Không thay thế rule bằng AI/ML.** Giữ Zeek script, Suricata signature và Intel Framework làm lớp phát hiện chính xác cao; AI/ML là lớp bổ sung để bắt hành vi biến thể, giảm cảnh báo nhiễu và ưu tiên hóa.
2. **Dùng kiến trúc hybrid nhiều lớp:**
   - Lớp 0: rule/signature hiện có.
   - Lớp 1: unsupervised anomaly detection trên log Zeek (Isolation Forest / KitNET) để bắt bất thường chưa biết.
   - Lớp 2: supervised detector cho các use case khó: **C2 beaconing, DNS tunneling, lateral movement, malware download**; scan/brute force dùng rule + ML hỗ trợ.
   - Lớp 3: risk fusion + correlation + MITRE ATT&CK mapping.
   - Lớp 4: LLM chỉ hỗ trợ triage/giải thích, không tự động chặn.
3. **Triển khai out-of-band trên VM riêng.** Filebeat gửi log JSON vào Redis (list, cho demo) hoặc Kafka (cho production); feature worker tính feature cửa sổ; inference service ghi detection vào Elasticsearch. Không chạy model nặng trên sensor Zeek.
4. **Ưu tiên triển khai:** feature pipeline + anomaly detection + beaconing/DNS tunneling trước; sau đó lateral movement, malware download, risk fusion và LLM triage.
5. **Bắt buộc có MLOps tối thiểu:** label store, model registry, đánh giá theo kịch bản, drift monitoring, retraining có kiểm soát, shadow/canary và rollback.
6. **Chỉ dùng metadata mạng.** Không thu payload, không lưu nội dung người dùng; ưu tiên quyền tối thiểu, TLS và audit.

## 2. Các quyết định kiến trúc chính

| Vấn đề | Quyết định | Lý do |
|---|---|---|
| Vai trò của ML | Bổ sung, không thay thế rule | Rule có precision cao với hành vi đã biết; ML bắt biến thể và bất thường |
| Vị trí xử lý | Out-of-band trên VM ML riêng | Không tranh CPU/RAM với Zeek; dễ scale, replay, cập nhật model |
| Truyền dữ liệu | Filebeat → Redis list (demo) / Kafka (production) | Buffer, replay, tách consumer, giảm tải ES. Filebeat không ghi trực tiếp Redis Streams |
| Feature | Feature cửa sổ + entity profile + graph | Hành vi tấn công thể hiện qua chuỗi sự kiện, không chỉ một flow |
| Model | Isolation Forest/KitNET + Gradient Boosting (XGBoost/LightGBM) | Phù hợp dữ liệu tabular, nhanh, dễ giải thích; KitNET cho online |
| Deep learning | Để giai đoạn mở rộng | Cần nhiều dữ liệu, latency và khó giải thích hơn |
| LLM | Chỉ triage/giải thích, human-in-the-loop | Nghiên cứu cho thấy LLM hỗ trợ tốt nhưng chưa đủ tin cậy để tự quyết định |
| Auto-response | Chỉ với alert critical, confidence cao, có allowlist và audit | Tránh chặn nhầm, đảm bảo khả năng rollback |
| Đánh giá | PR-AUC, recall@FPR, FP/ngày, MTTD; test trên dữ liệu lab | Accuracy trên benchmark dễ gây ảo tưởng do lệch phân phối |

## 3. Cấu trúc tài liệu

| Tài liệu | Nội dung | Đối tượng đọc |
|---|---|---|
| [`01-research-report.md`](./01-research-report.md) | Báo cáo nghiên cứu: hiện trạng, các hướng AI/ML, bằng chứng, dataset, lựa chọn model, rủi ro | Nhóm đồ án, giảng viên |
| [`02-system-design.md`](./02-system-design.md) | Thiết kế chi tiết: kiến trúc, data contract, feature, model card, risk fusion, deployment, MLOps, bảo mật | Kỹ sư triển khai |
| [`03-implementation-plan.md`](./03-implementation-plan.md) | Kế hoạch triển khai theo pha, backlog, test, đánh giá, demo, traceability, risk register | Nhóm đồ án, người review |

## 4. Phạm vi tối thiểu (MVP) và bản đầy đủ

| Hạng mục | MVP | Bản đầy đủ |
|---|---|---|
| Dữ liệu | P0: JSON, ECS, benign baseline, harness 6 kịch bản | Thêm pretraining công khai, nhiều biến thể, label audit sâu |
| Detection | Rule + D1 anomaly + D5 beaconing + D7 DNS tunneling | Thêm D2 scan, D3 brute force, D4 malware, D6 lateral |
| Risk | Scorecard + dedup cơ bản | Logistic/correlation kill-chain, feedback loop |
| Response | Alert + manual block | Auto-block có guardrail, TTL, rollback, audit |
| LLM | Không | Triage optional, RAG, human review |
| MLOps | Model card + replay + version | MLflow, drift monitoring, shadow/canary |
| Demo | 4 kịch bản trọng tâm + benign | 6 kịch bản + biến thể né tránh + feedback |

**Khuyến nghị:** MVP vẫn đáp ứng yêu cầu "tích hợp AI/ML vào NDR" và có thể hoàn thành chắc chắn; bản đầy đủ dùng khi còn nguồn lực và muốn điểm cao hơn ở phần đánh giá/MLOps.

## 5. Phạm vi và giả định

- Hệ thống hiện có: sensor Zeek + Suricata trên SPAN, Filebeat, Elasticsearch/Kibana, response service gọi pfSense/CrowdSec và gửi Teams/Telegram/email.
- Sáu kịch bản: port scan, brute force SSH/FTP, malware download, C2 beaconing, lateral movement SMB/PsExec, DNS exfiltration.
- Môi trường lab: các dải `192.168.217.0/24` (LAN), `192.168.230.0/24` (MGMT), `192.168.85.0/24` (WAN) như trong tài liệu gốc.
- Log Zeek được xuất JSON và chuẩn hóa ECS; có `uid`, `community_id`, JA3/JA4 (nếu bật package).
- Tài liệu này là **thiết kế mức hệ thống**, không phải mã nguồn hoàn chỉnh. Các snippet trong phần phụ lục là khung để triển khai.

## 6. Cách đọc nhanh

- Cần hiểu **vì sao chọn hướng này**: đọc `01-research-report.md`, mục 1–6.
- Cần **thiết kế để triển khai**: đọc `02-system-design.md`, mục 2–8.
- Cần **chia việc và tiêu chí nghiệm thu**: đọc `03-implementation-plan.md`, mục 3–7.
- Cần **demo đồ án**: đọc `03-implementation-plan.md`, mục 11.

## 7. Trạng thái

- Phiên bản: `v1.0` — bản thiết kế nền tảng.
- Việc cần nhóm chốt: phiên bản Zeek và log schema, dung lượng dữ liệu lab, chính sách auto-block, có dùng LLM hay không, mức đầu tư cho graph/sequence model.
- Mọi ngưỡng trong tài liệu là **giả thuyết cần hiệu chỉnh bằng thực nghiệm**, không phải cam kết kết quả.
