# Tiến độ triển khai NDR + AI/ML

> Cập nhật lần cuối: 2026-11-14  
> Nguồn phase/detector: [`03-implementation-plan.md`](./03-implementation-plan.md) (P0–P4, D1–D9)  
> Quy ước trạng thái: `Chưa bắt đầu` · `Đang làm` · `Hoàn thành (synthetic)` · `Hoàn thành (lab)` · `Tạm hoãn`

## 1. Tổng quan

| Hạng mục | Trạng thái | Bằng chứng | Ghi chú |
|---|---|---|---|
| ML foundation + D1 | Hoàn thành (synthetic) | `ndr/anomaly/`, 22 test D1; `uv run ndr demo --workdir /tmp/ndr-demo --seed 42` | 280 detections; attack recall 0.75; 1 FP/4 h = 6 FP/day; slow scan chưa bắt |
| D5 beaconing | Hoàn thành (synthetic) | `ndr/beacon/`, `ndr/synth/beacon.py`; `uv run ndr beacon-demo --workdir /tmp/ndr-beacon-demo --seed 42` | 309 detections; attack recall 1.00; test_recall 1.00; test_fp_per_day 0.00 |
| D7 DNS tunneling | Hoàn thành (synthetic) | `ndr/dns/`, `ndr/features/dns.py`, `ndr/synth/dns.py`; `uv run ndr dns-demo --workdir /tmp/ndr-dns-demo --seed 42` | 971 detections; attack recall 1.00; test_recall 1.00; test_fp_per_day 0.00 |
| NDR thật (Zeek/ELK) | Đang làm | Tài liệu thiết kế; chưa có log Zeek/lab thật | Cần chốt schema, mẫu log, ECS/index template |

## 2. Tiến độ theo pha

| Pha | Gate | Trạng thái | Đã có | Còn thiếu |
|---|---|---|---|---|
| P0 — Nền tảng dữ liệu và baseline | Replay 6 kịch bản; baseline rule-only | Đang làm | Synthetic harness, contracts, ground truth, D1/D5/D7 corpus | Log Zeek thật, ECS/index template, Filebeat/bus, baseline rule-only |
| P1 — Anomaly detection real-time | Score end-to-end; FP trong ngưỡng | Đang làm | D1 offline pipeline + tests; threshold/FP report | Bus/Redis, inference service, Elasticsearch/Kibana dashboard |
| P2 — Supervised detectors | Mỗi kịch bản đạt ngưỡng tối thiểu | Đang làm | D5, D7 synthetic hoàn thành; D1 fallback anomaly | D2, D3, D4, D6 |
| P3 — Risk fusion, response, LLM | Alert queue; auto-block an toàn | Chưa bắt đầu | `AlertEvent`/`FeedbackEvent` contracts | Risk engine, dedup/correlation, response guardrail, LLM triage |
| P4 — MLOps, đánh giá cuối, demo | Tái lập + demo thành công | Chưa bắt đầu | — | MLflow registry, CI, drift, shadow/canary, báo cáo cuối |

## 3. Detector

| ID | Model | Trạng thái | Artifact | Metric synthetic | Ghi chú |
|---|---|---|---|---|---|
| D1 | `anomaly_iforest` | Hoàn thành (synthetic) | `ndr/anomaly/` | 280 detections; recall 0.75; 1 FP/4 h = 6 FP/day | Fast scan/beacon/exfil detected; slow scan missed; per-host 5-minute conn |
| D2 | `scan_lgbm` | Chưa bắt đầu | — | — | Rule hiện có vẫn là lớp chính |
| D3 | `bruteforce_lgbm` | Chưa bắt đầu | — | — | Cần `ssh.log`/`ftp.log` |
| D4 | `malware_xgb` | Chưa bắt đầu | — | — | Cần `http.log`/`files.log`/intel |
| D5 | `beaconing_lgbm_iforest` | Hoàn thành (synthetic) | `ndr/beacon/` | test_recall 1.00; test_fp_per_day 0.00; 309 detections | LightGBM + IF, isotonic calibration, native SHAP, host-pair 10-minute conn |
| D6 | `lateral_lgbm` | Chưa bắt đầu | — | — | Cần SMB/DCE-RPC |
| D7 | `dns_tunnel_lgbm` | Hoàn thành (synthetic) | `ndr/dns/` | test_recall 1.00; test_fp_per_day 0.00; 971 detections | `dns.log`; lexical + window features, LightGBM + isotonic calibration, native SHAP, host-domain 5-minute windows |
| D8 | `risk_scorecard` | Chưa bắt đầu | `ndr/contracts.py` (`AlertEvent`) | — | Chờ D5 + D7 để có nhiều tín hiệu |
| D9 | `llm_triage` | Chưa bắt đầu | `ndr/contracts.py` (`AiSummary`) | — | Chỉ contract; chưa có runtime/RAG |

## 4. Nhật ký milestone

| Ngày | Milestone | Kết quả | Bằng chứng |
|---|---|---|---|
| 2026-11-14 | ML foundation + D1 | 22 tests; 280 detections; attack recall 0.75; 1 FP/4 h = 6 FP/day; fast scan/beacon/exfil detected, slow scan missed | `uv run pytest -q`; `uv run ndr demo --workdir /tmp/ndr-demo --seed 42` |
| 2026-11-14 | D5 beaconing | 29 tests toàn bộ; 309 detections; attack recall 1.00; metadata `test_recall=1.00`, `test_fp_per_day=0.00`; report toàn bộ benign 3 FP/3 h = 24 FP/day (tính cả train/val) | `uv run pytest -q`; `uv run ndr beacon-demo --workdir /tmp/ndr-beacon-demo --seed 42` |
| 2026-11-14 | D7 DNS tunneling | 43 tests toàn bộ; 971 detections; attack recall 1.00; 6/6 attack runs detected; metadata `test_recall=1.00`, `test_fp_per_day=0.00`; report 1 FP/3 h = 8 FP/day | `uv run pytest -q`; `uv run ndr dns-demo --workdir /tmp/ndr-dns-demo --seed 42` |

### Ghi chú triển khai D7

- Nhịp benign nhanh hơn plan: browsing 1–4 s, update 25 ± 5 s, AV 20 ± 3 s. Lý do: `DNS_MIN_EVENTS=10` cho mỗi cửa sổ 5 phút `(host, parent)`; nhịp 60 s/30 s của plan chỉ tạo 5–10 query/cửa sổ nên gần như không có snapshot benign.
- Split benign là `[:3]/[3:5]/[5:]` (6/3/3 run) thay vì `[:4]/[4:5]/[5:]` (7/2/3). Split của plan chỉ có browsing trong validation, khiến CDN/AV/update benign vượt threshold và `test_fp_per_day=23904`; split hiện tại đưa FP về 0.

## 5. Việc tiếp theo

1. D8 risk scorecard: gộp D1 + D5 + D7, dedup/correlation, MITRE mapping.
2. LLM triage harness: mock alerts, RAG playbook, JSON schema, guardrail, eval so với template.
3. Real Zeek adapter: `ndr inspect`, log-schema freeze (bao gồm `dns.log` thật).
4. Thu mẫu log Zeek thật và chuyển trạng thái detector từ `(synthetic)` sang `(lab)`.

## 6. Cách cập nhật

- Mỗi milestone: thêm một dòng vào `## 4. Nhật ký milestone`, cập nhật đúng dòng phase/detector liên quan; không xóa lịch sử.
- Chỉ dùng `Hoàn thành (lab)` khi đã có log Zeek thật + `run.json` + replay tất định; nếu chỉ có synthetic thì dùng `Hoàn thành (synthetic)`.
- Mỗi metric phải ghi kèm command và seed đã tạo ra nó.
- Nếu một detector bị tạm dừng, đổi trạng thái thành `Tạm hoãn` và ghi lý do trong cột ghi chú.
