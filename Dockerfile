FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

# Web 管理页（HTTP）与 TCP 访问网关（TCP）分别监听
EXPOSE 8000 9001

# 重要：网关是进程内单例，必须只运行单个 uvicorn worker。
# 默认 worker 数即为 1；不要追加 --workers N（N>1）或 --reload。
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
