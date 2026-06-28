FROM python:3.13-slim

WORKDIR /app

COPY app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./

EXPOSE 8501

CMD ["streamlit", "run", "interfaz2.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--server.enableCORS=false", \
     "--server.enableXsrfProtection=false"]
