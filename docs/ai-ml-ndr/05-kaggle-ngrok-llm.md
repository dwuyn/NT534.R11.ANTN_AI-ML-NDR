# Kaggle GPU + ngrok làm LLM provider

> Phạm vi: chạy thử/batch evaluation cho D9 triage. Không dùng làm service production hoặc real-time NDR.
> Provider phía repo là `OpenAICompatibleProvider` trong `ndr/llm/provider.py`.

## 1. Kiến trúc

```text
Kaggle GPU: Qwen2.5-7B-Instruct (4-bit) + vLLM OpenAI server :8000
        │
        └── ngrok HTTPS tunnel
                │
Máy NDR: ndr llm-eval / llm-triage --provider openai
```

- Kaggle chỉ cần outbound Internet; không cần inbound port.
- ngrok tạo URL HTTPS công khai, có thể đổi sau mỗi session.
- Repo chỉ gửi alert metadata + playbook; không gửi raw packet/payload.

## 2. Chuẩn bị Kaggle

Tạo notebook, chọn **GPU T4 x2** hoặc **P100**. Thêm secrets trong Kaggle:

- `NGROK_AUTHTOKEN`: token từ dashboard ngrok.
- `NDR_LLM_API_KEY`: chuỗi ngẫu nhiên đủ mạnh, dùng làm bearer token giữa máy NDR và vLLM.

Kiểm tra GPU:

```python
!nvidia-smi
```

Cài dependency:

```python
!pip install -q -U vllm bitsandbytes accelerate pyngrok
```

> Nếu vLLM xung đột dependency với image Kaggle, dùng `llama.cpp` + GGUF Q4_K_M thay thế; provider phía repo không đổi.

## 3. Chạy vLLM

```python
import os
import subprocess

model = "Qwen/Qwen2.5-7B-Instruct"
log = open("/kaggle/working/vllm.log", "w")

server = subprocess.Popen(
    [
        "python", "-m", "vllm.entrypoints.openai.api_server",
        "--model", model,
        "--dtype", "float16",
        "--quantization", "bitsandbytes",
        "--load-format", "bitsandbytes",
        "--max-model-len", "8192",
        "--gpu-memory-utilization", "0.90",
        "--max-num-seqs", "4",
        "--api-key", os.environ["NDR_LLM_API_KEY"],
        "--port", "8000",
    ],
    stdout=log,
    stderr=subprocess.STDOUT,
)
print("vLLM pid:", server.pid)
```

Chờ server sẵn sàng:

```python
import time
import urllib.request

url = "http://127.0.0.1:8000/v1/models"
request = urllib.request.Request(
    url,
    headers={"Authorization": f"Bearer {os.environ['NDR_LLM_API_KEY']}"},
)

for attempt in range(120):
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            print(response.read().decode()[:500])
        break
    except Exception as exc:
        print(f"waiting {attempt + 1}/120: {exc}")
        time.sleep(5)
else:
    print(open("/kaggle/working/vllm.log").read()[-4000:])
    raise RuntimeError("vLLM did not start")
```

## 4. Mở ngrok

```python
from pyngrok import ngrok

ngrok.set_auth_token(os.environ["NGROK_AUTHTOKEN"])
tunnel = ngrok.connect(8000, "http")
print(tunnel.public_url + "/v1")
```

Giữ notebook session mở. URL có dạng:

```text
https://<random>.ngrok-free.app/v1
```

## 5. Cấu hình phía máy NDR

Dùng biến môi trường, tránh đưa token vào shell history:

```bash
export NDR_LLM_BASE_URL='https://<random>.ngrok-free.app/v1'
export NDR_LLM_MODEL='Qwen/Qwen2.5-7B-Instruct'
export NDR_LLM_API_KEY='<NDR_LLM_API_KEY>'
```

Chạy evaluation 6 alert synthetic:

```bash
uv run ndr llm-eval \
  --provider openai \
  --timeout 300 \
  --out data/reports/llm-eval-qwen.json
```

Chạy triage trên alert thật đã export:

```bash
uv run ndr llm-triage \
  --provider openai \
  --timeout 300 \
  --alerts data/alerts/alerts.jsonl \
  --out data/triage/triage-qwen.jsonl \
  --audit data/audit/llm-qwen.jsonl
```

Nếu server không hỗ trợ `response_format`, thêm `--no-json-mode`:

```bash
uv run ndr llm-eval --provider openai --no-json-mode
```

## 6. Kiểm tra và xử lý lỗi

| Lỗi | Nguyên nhân / cách xử lý |
|---|---|
| `HTTP 401` | `NDR_LLM_API_KEY` không khớp `--api-key` của vLLM |
| `HTTP 404` | `NDR_LLM_BASE_URL` thiếu `/v1` hoặc sai tunnel |
| `HTTP 400` với `response_format` | thêm `--no-json-mode` |
| `timed out` | tăng `--timeout`, giảm `--max-tokens` |
| CUDA OOM | giảm `--max-model-len` xuống 4096, giảm `--gpu-memory-utilization` |
| JSON sai schema | model chưa theo prompt; bật JSON mode hoặc dùng model/guided decoding tốt hơn |
| MITRE mismatch | model phải copy nguyên `mitre` từ alert; guardrail sẽ từ chối |
| ngrok URL đổi | cập nhật `NDR_LLM_BASE_URL` sau mỗi session |

## 7. Giới hạn cần ghi trong báo cáo

- Kaggle session tối đa khoảng 12 giờ, GPU quota khoảng 30 giờ/tuần; không có SLA.
- ngrok URL công khai; chỉ dùng token mạnh, dừng tunnel sau demo.
- Không gửi log lab thật nếu chưa được phép; ưu tiên alert metadata đã redact.
- Kết quả phụ thuộc model/version/quantization; ghi `provider`, `model`, timeout và commit hash.
- Đây là **offline/batch evaluation**, không phải bằng chứng real-time inference hay production availability.
