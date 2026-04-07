FROM python:3.11-slim-bookworm

WORKDIR /app


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#copy app
COPY . .

#hf spaces expects the port to be 7860
EXPOSE 7860

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
