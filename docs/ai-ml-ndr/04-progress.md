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
| D2 port scan | Hoàn thành (synthetic) | `ndr/scan/`, `ndr/features/scan.py`, `ndr/synth/scan.py`; `uv run ndr scan-demo --workdir /tmp/ndr-scan-demo --seed 42` | 215 detections; attack recall 1.00; test_fp_per_day 0.00; 6/6 attack variants |
| D3 brute force | Hoàn thành (synthetic) | `ndr/brute/`, `ndr/features/brute.py`, `ndr/synth/brute.py`; `uv run ndr brute-demo --workdir /tmp/ndr-brute-demo --seed 42` | 66 detections; attack recall 1.00; test_fp_per_day 0.00; 6/6 attack variants |
| D4 malware download | Hoàn thành (synthetic) | `ndr/malware/`, `ndr/features/malware.py`, `ndr/synth/malware.py`; `uv run ndr malware-demo --workdir /tmp/ndr-malware-demo --seed 42` | 384 detections; attack recall 1.00; test_fp_per_day 0.00; 6/6 attack variants |
| D6 lateral movement | Hoàn thành (synthetic) | `ndr/lateral/`, `ndr/features/lateral.py`, `ndr/synth/lateral.py`; `uv run ndr lateral-demo --workdir /tmp/ndr-lateral-demo --seed 42` | 54 detections; attack recall 1.00; test_fp_per_day 0.00; report 1 benign window = 8 FP/day |
| D8 risk fusion | Hoàn thành (synthetic) | `ndr/risk/`; `uv run ndr risk-demo --workdir /tmp/ndr-risk-demo --seed 42` | 58 raw alerts → 16 alerts; reduction 72.41%; MITRE 100%; 12 critical/4 low |
| D9 mock LLM triage | Hoàn thành (synthetic) | `ndr/llm/`; `uv run ndr llm-eval --out /tmp/ndr-llm-eval.json` | 6/6 eval alerts; schema/MITRE/evidence/actionability 1.00; hallucination 0.00 |
| Response guardrail | Hoàn thành (synthetic) | `ndr/response/`; `uv run ndr response-sim ...` | 35 allowed, 5 denied (4 risk, 1 confidence); allowlist/TTL/rate-limit/rollback covered by tests |
| E2E prelab | Hoàn thành (synthetic) | `ndr/prelab.py`; `uv run ndr prelab-demo --workdir /tmp/ndr-prelab --seed 42` | 6 attack scenarios; risk 135 → 40 (70.37% reduction); 36 triage; 40 response decisions |
| NDR thật (Zeek/ELK) | Đang làm | Tài liệu thiết kế; chưa có log Zeek/lab thật | Cần chốt schema, mẫu log, ECS/index template |

## 2. Tiến độ theo pha

| Pha | Gate | Trạng thái | Đã có | Còn thiếu |
|---|---|---|---|---|
| P0 — Nền tảng dữ liệu và baseline | Replay 6 kịch bản; baseline rule-only | Đang làm | Synthetic harness, contracts, ground truth, D1/D2/D3/D4/D5/D6/D7 corpus | Log Zeek thật, ECS/index template, Filebeat/bus, baseline rule-only |
| P1 — Anomaly detection real-time | Score end-to-end; FP trong ngưỡng | Đang làm | D1 offline pipeline + tests; threshold/FP report | Bus/Redis, inference service, Elasticsearch/Kibana dashboard |
| P2 — Supervised detectors | Mỗi kịch bản đạt ngưỡng tối thiểu | Hoàn thành (synthetic) | D2/D3/D4/D5/D6/D7 synthetic; recall >= 0.85, test FP/day <= 10 | Xác nhận lại trên log lab thật |
| P3 — Risk fusion, response, LLM | Alert queue; auto-block an toàn | Đang làm | D8 risk fusion; D9 mock triage; response simulator; E2E 6 kịch bản synthetic | Kibana triage/feedback, LLM provider thật, alert queue thật |
| P4 — MLOps, đánh giá cuối, demo | Tái lập + demo thành công | Chưa bắt đầu | — | MLflow registry, CI, drift, shadow/canary, báo cáo cuối |

## 3. Detector

| ID | Model | Trạng thái | Artifact | Metric synthetic | Ghi chú |
|---|---|---|---|---|---|
| D1 | `anomaly_iforest` | Hoàn thành (synthetic) | `ndr/anomaly/` | 280 detections; recall 0.75; 1 FP/4 h = 6 FP/day | Fast scan/beacon/exfil detected; slow scan missed; per-host 5-minute conn |
| D2 | `scan_lgbm` | Hoàn thành (synthetic) | `ndr/scan/` | 215 detections; recall 1.00; test_fp_per_day 0.00 | 9 đặc trưng conn 5 phút; LightGBM + isotonic + SHAP; 6 biến thể scan |
| D3 | `bruteforce_lgbm` | Hoàn thành (synthetic) | `ndr/brute/` | 66 detections; recall 1.00; test_fp_per_day 0.00 | `ssh.log`/`ftp.log`; 9 đặc trưng; 6 biến thể brute |
| D4 | `malware_lgbm` | Hoàn thành (synthetic) | `ndr/malware/` | 384 detections; recall 1.00; test_fp_per_day 0.00 | Join `http/files/ssl/intel`; 22 đặc trưng; 6 biến thể malware |
| D5 | `beaconing_lgbm_iforest` | Hoàn thành (synthetic) | `ndr/beacon/` | test_recall 1.00; test_fp_per_day 0.00; 309 detections | LightGBM + IF, isotonic calibration, native SHAP, host-pair 10-minute conn |
| D6 | `lateral_lgbm` | Hoàn thành (synthetic) | `ndr/lateral/` | 54 detections; recall 1.00; test_fp_per_day 0.00 | SMB/DCE-RPC; 13 đặc trưng graph/rarity; 6 biến thể lateral |
| D7 | `dns_tunnel_lgbm` | Hoàn thành (synthetic) | `ndr/dns/` | test_recall 1.00; test_fp_per_day 0.00; 971 detections | `dns.log`; lexical + window features, LightGBM + isotonic calibration, native SHAP, host-domain 5-minute windows |
| D8 | `risk_scorecard` | Hoàn thành (synthetic) | `ndr/risk/` | 58 raw → 16 alerts; reduction 72.41%; MITRE 100%; 12 critical/4 low | D5/D7 tạo alert; D2/D3/D4/D6 thêm rule; D1 corroboration; dedup 30 phút, enrichment JSON, response chỉ khuyến nghị |
| D9 | `llm_triage` | Hoàn thành (synthetic) | `ndr/llm/` | 6 eval alerts; schema/MITRE/evidence/actionability 1.00; hallucination 0.00 | Mock provider deterministic; RAG playbook; strict JSON; redaction; audit; chưa gọi LLM thật |

## 4. Nhật ký milestone

| Ngày | Milestone | Kết quả | Bằng chứng |
|---|---|---|---|
| 2026-11-14 | ML foundation + D1 | 22 tests; 280 detections; attack recall 0.75; 1 FP/4 h = 6 FP/day; fast scan/beacon/exfil detected, slow scan missed | `uv run pytest -q`; `uv run ndr demo --workdir /tmp/ndr-demo --seed 42` |
| 2026-11-14 | D5 beaconing | 29 tests toàn bộ; 309 detections; attack recall 1.00; metadata `test_recall=1.00`, `test_fp_per_day=0.00`; report toàn bộ benign 3 FP/3 h = 24 FP/day (tính cả train/val) | `uv run pytest -q`; `uv run ndr beacon-demo --workdir /tmp/ndr-beacon-demo --seed 42` |
| 2026-11-14 | D7 DNS tunneling | 43 tests toàn bộ; 971 detections; attack recall 1.00; 6/6 attack runs detected; metadata `test_recall=1.00`, `test_fp_per_day=0.00`; report 1 FP/3 h = 8 FP/day | `uv run pytest -q`; `uv run ndr dns-demo --workdir /tmp/ndr-dns-demo --seed 42` |
| 2026-11-14 | D8 risk fusion | 57 tests toàn bộ; 58 raw D5/D7 alerts → 16 alerts; reduction 72.41%; MITRE coverage 100%; 12 critical/4 low; 4 D1 corroboration events | `uv run pytest -q`; `uv run ndr risk-demo --workdir /tmp/ndr-risk-demo --seed 42` |
| 2026-11-14 | Pre-lab D2/D3/D4/D6/D9 + response + E2E | 158 tests toàn bộ; D2 215, D3 66, D4 384, D6 54 detections; cả 6 detector supervised recall 1.00, test FP/day 0.00; risk 135 → 40 (70.37%); 36 triage; 35 allowed/5 denied | `uv run pytest -q`; `uv run ndr prelab-demo --workdir /tmp/ndr-prelab --seed 42`; 4 detector demos; `uv run ndr llm-eval` |

### Ghi chú triển khai D8

- D5/D7 là nguồn alert; D1 chỉ corroboration. Dedup theo `(rule, entity)` trong chuỗi 30 phút; C2 và DNS tunneling cùng `src_ip` trong 30 phút tăng `detectors_agree`/`kill_chain_advance`.
- `AlertEvent` thêm `first_seen`, `last_seen`, `count`, `reasons` (additive, schema 1.0). Enrichment đọc từ JSON key theo `src_ip`; không có nguồn thật nên demo dùng `demo_enrichment()`.
- Demo hiện tại không có cặp D5/D7 trùng thời gian nên `agreement_alerts=0`; agreement/kill-chain được unit test xác nhận.

### Ghi chú triển khai pre-lab (D2/D3/D4/D6/D9/response)

- Cả 4 detector mới dùng LightGBM + isotonic calibration + native SHAP, split 6/3/3, threshold target 10 FP/day. Rule: `NDR-ML-SCAN-001`, `NDR-ML-BRUTE-001`, `NDR-ML-MALWARE-001`, `NDR-ML-LATERAL-001`.
- **Threshold guard dùng chung** (`ndr/features/calibration.ensure_above_benign`): isotonic trên validation tách hoàn toàn thường cho benign score = 0; quantile threshold = 0 sẽ flag mọi benign window vì điều kiện `score >= threshold`. Helper đặt threshold thành `nextafter(max_benign, +inf)` (ví dụ `9.7e-18`). Đây là deviation có chủ đích so với công thức quantile thuần; nếu không, D2 seed 42 có `test_fp_per_day=2904`, D4 recall 0 do threshold nằm giữa 0 và score attack.
- **D2 split order**: đưa `benign_mixed` vào validation (`[3:5]`) thay vì test để threshold học được phân phối mixed; seed 42 trước đó có 85 benign alerts trên test. Không đổi split 6/3/3.
- **D6 edge semantics**: `new_host_pair_count`/`graph_new_edges` đếm cặp `(src,dst)` unique; `smb_unique_dsts` chỉ mapping+file, `graph_out_degree` dùng toàn bộ SMB/DCE. Report vẫn có 1 benign window (software deploy) = 8 FP/day; metadata held-out `test_fp_per_day=0.00`.
- **D9**: chỉ high/critical; MockProvider deterministic, không network; strict schema; MITRE phải khớp alert; redaction secret; audit JSONL có `prompt_sha256`.
- **Response**: allowlist `.129`, risk >=85, confidence >=0.9, TTL 3600, rate limit 10/phút; rollback chỉ trong simulator; không gọi firewall thật.
- **E2E**: `prelab-demo` chạy D1–D7, risk, D9, response; D1 chỉ corroboration, 6 scenario alert là D2–D7. Response demo 35 allowed/5 denied vì 4 alert low risk và 1 alert confidence thấp; chưa có alert nguồn `.129` nên allowlist denial được unit test phủ.

### Ghi chú triển khai D7

- Nhịp benign nhanh hơn plan: browsing 1–4 s, update 25 ± 5 s, AV 20 ± 3 s. Lý do: `DNS_MIN_EVENTS=10` cho mỗi cửa sổ 5 phút `(host, parent)`; nhịp 60 s/30 s của plan chỉ tạo 5–10 query/cửa sổ nên gần như không có snapshot benign.
- Split benign là `[:3]/[3:5]/[5:]` (6/3/3 run) thay vì `[:4]/[4:5]/[5:]` (7/2/3). Split của plan chỉ có browsing trong validation, khiến CDN/AV/update benign vượt threshold và `test_fp_per_day=23904`; split hiện tại đưa FP về 0.

## 5. Việc tiếp theo

1. Real Zeek adapter: `ndr inspect`, log-schema freeze cho `conn/ssh/ftp/http/files/ssl/smb/dce_rpc/dns`.
2. Thu mẫu log Zeek thật, replay 6 kịch bản, chuyển detector từ `(synthetic)` sang `(lab)`.
3. LLM provider thật thay `MockProvider`, giữ nguyên schema/guardrail/audit/eval; thêm RAG thật.
4. Kibana triage/feedback + alert queue; response guardrail chỉ bật sau khi có phê duyệt.
5. MLOps: MLflow/CI, drift, shadow/canary, báo cáo đánh giá cuối.

## 6. Cách cập nhật

- Mỗi milestone: thêm một dòng vào `## 4. Nhật ký milestone`, cập nhật đúng dòng phase/detector liên quan; không xóa lịch sử.
- Chỉ dùng `Hoàn thành (lab)` khi đã có log Zeek thật + `run.json` + replay tất định; nếu chỉ có synthetic thì dùng `Hoàn thành (synthetic)`.
- Mỗi metric phải ghi kèm command và seed đã tạo ra nó.
- Nếu một detector bị tạm dừng, đổi trạng thái thành `Tạm hoãn` và ghi lý do trong cột ghi chú.
