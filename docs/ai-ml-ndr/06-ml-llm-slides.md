---
marp: true
theme: default
paginate: true
size: 16:9
header: 'NDR + AI/ML'
footer: 'NT534 · ML/LLM layer'
style: |
  section {
    font-size: 27px;
  }
  table {
    font-size: 20px;
  }
  code {
    font-size: 21px;
  }
---

<!-- _class: lead -->

# AI/ML trong đồ án NDR

## Rule-first, ML-augmented, LLM-assisted

**ML phát hiện hành vi · Risk fusion ưu tiên · LLM hỗ trợ triage**

<!--
SPEAKER NOTES — Slide 1 (1 phút)

Mở đầu: Đồ án không thay thế NDR rule-based bằng AI/ML. Hệ thống hiện có Zeek/Suricata làm lớp phát hiện chính. Phần em bổ sung gồm ba lớp: ML phát hiện hành vi, risk fusion gộp tín hiệu, và LLM hỗ trợ analyst đọc alert. Từ khóa để thầy/cô nhớ: rule-first, ML-augmented, LLM-assisted.
-->

---

# Vấn đề và mục tiêu

- Rule bắt tốt hành vi **đã biết**, nhưng dễ bỏ sót biến thể:
  - scan chậm
  - beacon có jitter
  - DNS tunnel entropy thấp
- Alert thô nhiều, thiếu ngữ cảnh và ưu tiên.
- Analyst cần: **evidence, MITRE, lý do, action**.

**Mục tiêu:** thêm lớp ML/LLM nhưng **không thay rule**, **không auto-block**.

<!--
SPEAKER NOTES — Slide 2 (1.5 phút)

Vì sao cần ML? Rule rất tốt với signature đã biết, nhưng kẻ tấn công có thể thay đổi nhịp, giảm tốc độ, hoặc làm nhiễu để né ngưỡng cố định. ML nhìn nhiều feature cùng lúc nên bắt được tổ hợp bất thường tốt hơn. Vấn đề thứ hai là alert quá nhiều; analyst cần risk score và giải thích. Mục tiêu không phải thay rule mà là bổ sung một lớp phát hiện biến thể, sau đó fusion và LLM hỗ trợ triage.
-->

---

# Ba lớp, ba vai trò

| Lớp | Làm gì | Không làm gì |
|---|---|---|
| **Rule** | Bắt signature đã biết; precision cao | Không bắt biến thể tốt |
| **ML** | Học pattern từ feature số | Không thay thế hoàn toàn rule |
| **LLM** | Giải thích alert, gợi ý action | Không phát hiện, không auto-block |

**Nguyên tắc:** ML bổ sung, LLM chỉ hỗ trợ con người.

<!--
SPEAKER NOTES — Slide 3 (1 phút)

Ba lớp này không cạnh tranh nhau mà bổ sung nhau. Rule cho cái đã biết và dễ audit. ML cho cái chưa biết hoặc biến thể. LLM không phát hiện tấn công; nó chỉ đọc alert đã có và tạo bản tóm tắt có cấu trúc. Đây là lý do em không đưa LLM vào đường phát hiện chính.
-->

---

# Kiến trúc tổng thể

```text
Zeek metadata
   │
   ▼
Window + Feature
   │
   ├── D1 anomaly (unsupervised)
   ├── D2 scan
   ├── D3 brute force
   ├── D4 malware
   ├── D5 beacon
   ├── D6 lateral
   └── D7 DNS tunnel
          │
          ▼
   D8 risk fusion
   (dedup, scorecard, MITRE)
          │
          ▼
      Alert high/critical
          │
          ├── D9 LLM triage
          └── Response policy / simulator
```

<!--
SPEAKER NOTES — Slide 4 (1.5 phút)

Đây là luồng chính. Đầu vào là metadata từ Zeek, không phải payload. Mỗi detector có cửa sổ và feature riêng. D1 là unsupervised, D2 đến D7 là supervised. Các detection đi vào D8 để gộp, khử trùng lặp, gắn risk và MITRE. Alert high/critical mới đi tiếp sang LLM triage hoặc response policy. D1 không tự tạo alert cuối; nó chỉ là tín hiệu corroboration vì anomaly dễ nhiễu.
-->

---

# ML pipeline hoạt động thế nào?

1. **Log** Zeek: conn, dns, ssh, ftp, http, files, ssl, smb, dce_rpc
2. **Gom cửa sổ** theo host / host-pair / host-domain
3. **Tính feature** thành vector số
4. **Model** cho ra score
5. **Threshold** quyết định detection
6. **D8 fusion** tạo alert cuối

```python
features = [duration, bytes, ports, failed_ratio, entropy, ...]
score = model.predict_proba(features)
if score >= threshold:
    emit_detection()
```

<!--
SPEAKER NOTES — Slide 5 (2 phút)

ML không tự đọc log hiểu như con người. Nó làm theo pipeline cố định: gom sự kiện theo cửa sổ, tính feature, đưa vector số vào model, nhận score, rồi so với threshold. Ví dụ D5 gom 10 phút của một cặp host, tính khoảng cách trung bình, độ lệch chuẩn, autocorrelation, tỷ lệ byte giống nhau. Vector đó đi vào model. Nếu score vượt threshold thì sinh detection. Detector chỉ sinh event theo cửa sổ; alert cuối là do D8 fusion.
-->

---

# D1: Isolation Forest

## Ý tưởng

- Cắt dữ liệu ngẫu nhiên nhiều lần.
- Điểm bình thường nằm trong vùng đông → khó cô lập.
- Điểm bất thường bị cô lập **sau ít lần cắt**.

## Trong đồ án

- Unsupervised: chỉ fit trên benign.
- 18 feature conn, cửa sổ 5 phút / host.
- Score bất thường + threshold.
- Dùng làm **corroboration**, không tự alert.

<!--
SPEAKER NOTES — Slide 6 (2 phút)

Isolation Forest là thuật toán anomaly detection. Hãy tưởng tượng mỗi cây chọn ngẫu nhiên một feature và một ngưỡng để cắt dữ liệu. Điểm bình thường nằm trong vùng đông nên phải cắt nhiều lần mới cô lập. Điểm bất thường nằm xa nên bị cô lập nhanh. Đồ án dùng nó cho D1 vì D1 không có label tấn công; mình chỉ học baseline benign theo từng host. Hạn chế là bất thường không đồng nghĩa tấn công, nên D1 chỉ đóng góp tín hiệu vào D8, không tự tạo alert.
-->

---

# D2–D7: LightGBM supervised

## Vì sao supervised?

- Đã biết kịch bản và có label.
- Feature dạng bảng, số chiều vừa phải.
- Cần score + giải thích.

## LightGBM

- Nhiều cây quyết định nhỏ.
- Cây sau sửa lỗi cây trước.
- Nhanh, nhẹ, có **SHAP**.

**Không dùng deep learning** vì dữ liệu nhỏ, cần giải thích, latency thấp.

<!--
SPEAKER NOTES — Slide 7 (2 phút)

Với D2 đến D7, mình biết trước kịch bản nên dùng supervised. LightGBM là gradient boosting: xây nhiều cây nhỏ, mỗi cây sau học phần cây trước còn sai. Nó phù hợp dữ liệu tabular, nhanh trên CPU, và có SHAP để giải thích vì sao một cửa sổ bị chấm cao. Deep learning không được chọn vì dataset nhỏ, dễ overfit, khó giải thích và không cần thiết cho phạm vi này.
-->

---

# Feature engineering theo kịch bản

| Detector | Tín hiệu chính | Vì sao |
|---|---|---|
| D2 scan | nhiều cổng đích, tỷ lệ lỗi, host mới | scan tạo nhiều kết nối thất bại |
| D3 brute | fail count, unique users, success after fail | brute có chuỗi fail |
| D4 malware | file rarity, MIME mismatch, intel hit | malware thường hiếm/lạ |
| D5 beacon | interval mean/std, autocorr, FFT, same-size | C2 có chu kỳ |
| D6 lateral | SMB dsts, graph degree, betweenness | lateral lan theo quan hệ |
| D7 DNS tunnel | entropy, length, unique subdomain, query rate | tunnel nhồi dữ liệu vào tên miền |

<!--
SPEAKER NOTES — Slide 8 (2 phút)

Mỗi detector có feature riêng vì mỗi hành vi để lại dấu vết số khác nhau. Scan thì nhiều cổng và nhiều kết nối lỗi. Brute force thì nhiều login fail, nhiều user, đôi khi thành công sau chuỗi fail. Malware thì file hiếm, MIME lạ, có intel hit. Beacon thì khoảng cách đều, kích thước ổn định, autocorrelation cao. Lateral thì phải nhìn quan hệ SMB giữa nhiều host. DNS tunnel thì subdomain dài, entropy cao, query rate lớn. Điểm chung: chỉ dùng metadata, không đọc payload.
-->

---

# Calibration, threshold và đánh giá

- Score thô **không phải xác suất**.
- Isotonic calibration ánh xạ score → xác suất.
- Threshold chọn theo **FP/ngày**, không theo 0.5.
- Chia train/validation/test theo **run** để tránh leakage.
- Metric: recall, precision, PR-AUC, FP/ngày.
- **Accuracy không phù hợp** vì dữ liệu mất cân bằng.

<!--
SPEAKER NOTES — Slide 9 (2 phút)

Phần này rất quan trọng. Model trả score thô, nhưng 0.7 không có nghĩa là 70 phần trăm xác suất. Isotonic calibration học ánh xạ từ score sang xác suất thực nghiệm. Threshold được chọn theo ngân sách alert, ví dụ tối đa bao nhiêu false positive mỗi ngày, chứ không chọn 0.5. Dữ liệu chia theo run để tránh cùng một phiên tấn công nằm ở cả train và test. Metric dùng recall, precision, PR-AUC và FP/ngày; accuracy dễ gây hiểu nhầm vì attack rất ít.
-->

---

# D8: Risk fusion

## Không phải ML

- Dedup theo rule + entity.
- Chuỗi correlation 30 phút.
- Scorecard cộng/trừ điểm.
- Gắn MITRE, evidence, response recommendation.

## Vì sao deterministic?

- Cần audit rõ ràng.
- Chưa có label alert-level.
- Dễ giải thích với analyst và giảng viên.

<!--
SPEAKER NOTES — Slide 10 (1.5 phút)

D8 không phải ML. Nó là scorecard deterministic để gộp detection thành alert. Ví dụ D5 và D7 là nguồn alert mạnh; D2 đến D6 đóng góp rule; D1 chỉ corroboration. Nó khử trùng lặp theo rule và entity trong chuỗi 30 phút, cộng điểm theo intel, asset, agreement, kill chain, trừ điểm allowlist và lịch sử false positive. Mình chọn deterministic vì cần audit và chưa có label alert-level để học fusion.
-->

---

# D9: LLM triage

## LLM không phát hiện tấn công

- Chỉ chạy với alert **high/critical**.
- Input: alert JSON + playbook.
- Output JSON: summary, evidence, hypotheses, MITRE, actions, confidence, caveats.
- RAG đơn giản: tra playbook theo scenario.
- Không fine-tune; có thể thay model.

```text
Alert + Playbook → LLM → JSON có kiểm tra schema
```

<!--
SPEAKER NOTES — Slide 11 (2 phút)

LLM là mô hình ngôn ngữ đã huấn luyện sẵn; đồ án chỉ dùng inference, không train lại. Nó nhận alert JSON và playbook, rồi sinh JSON có cấu trúc gồm tóm tắt, evidence, giả thuyết, MITRE, action, confidence và caveats. RAG ở đây là mức đơn giản: tra playbook theo scenario rồi đưa vào prompt, chưa phải vector database. LLM không phát hiện tấn công; detector mới làm việc đó. LLM giúp analyst đọc alert nhanh hơn và thấy action gợi ý.
-->

---

# Guardrail cho LLM

- Strict schema Pydantic.
- MITRE phải **bằng đúng** alert.
- Evidence chỉ là ID có trong alert.
- Redact secret.
- Audit JSONL: provider, ok/error, prompt hash.
- Không auto-block; cần con người.

**LLM có thể bịa → guardrail phải từ chối.**

<!--
SPEAKER NOTES — Slide 12 (2 phút)

LLM có thể bịa hoặc bị prompt injection từ nội dung log. Vì vậy output phải đúng schema; MITRE phải khớp alert, không được tự nghĩ ra technique; evidence chỉ được lấy từ alert; secret bị redact; mọi lần gọi được audit. LLM không được gọi tool hay chặn IP. Nếu output sai, hệ thống reject và ghi audit. Đây là lý do LLM chỉ là lớp hỗ trợ, không phải lớp quyết định.
-->

---

# Hiện trạng và giới hạn

- ML: D1–D7 synthetic; lab adapter cho D1/D2/D3/D5/D7.
- D4/D6: mới synthetic vì lab chưa có malware scenario/Windows SMB victim.
- LLM: mock deterministic + provider OpenAI-compatible; chưa eval model thật.
- Response: simulator; chưa auto-block.
- Batch/offline; chưa real-time.
- Kết quả synthetic chỉ kiểm chứng pipeline, không đại diện lab.

<!--
SPEAKER NOTES — Slide 13 (1.5 phút)

Phần này nên nói thật để tránh overclaim. ML hiện chạy tốt trên synthetic và đã có adapter đọc raw Zeek cho D1, D2, D3, D5, D7. D4 và D6 chưa có kịch bản lab nên mới synthetic. LLM mới có mock deterministic và provider OpenAI-compatible; chưa chạy đánh giá model thật trên lab. Response chỉ là simulator, chưa auto-block. Hệ thống hiện là batch/offline, chưa real-time. Kết quả synthetic dùng để kiểm chứng wiring và guardrail, không phải để tuyên bố chất lượng lab.
-->

---

# Kết luận

## Ba điểm cần nhớ

1. **Rule-first:** ML bổ sung, không thay thế.
2. **ML phát hiện – fusion ưu tiên – LLM giải thích.**
3. **Guardrail + con người:** không auto-block.

> Giá trị của đồ án nằm ở kiến trúc hybrid, cách hiệu chỉnh theo FP/ngày, và guardrail cho LLM.

<!--
SPEAKER NOTES — Slide 14 (1 phút)

Kết lại ba ý. Một, hệ thống giữ rule làm nền. Hai, ML phát hiện hành vi, D8 fusion ưu tiên, LLM chỉ giải thích. Ba, mọi quyết định nguy hiểm đều có guardrail và con người. Giá trị học thuật không nằm ở một con số recall đẹp, mà ở kiến trúc hybrid, cách chọn threshold theo FP/ngày, và cách kiểm soát LLM. Em sẵn sàng nhận câu hỏi.
-->
