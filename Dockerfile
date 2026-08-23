FROM python:3.11-slim

# ping and traceroute are not part of the base Debian image; install them
# explicitly (iputils-ping provides `ping`, and `traceroute` is its own
# package). See README.md "Docker & Permissions" section for why the
# container needs NET_RAW capability at run time to actually use them.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_APP=run.py

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
