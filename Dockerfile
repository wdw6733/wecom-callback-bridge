FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY wecom_callback.py .
EXPOSE 18789
CMD ["python", "wecom_callback.py"]
