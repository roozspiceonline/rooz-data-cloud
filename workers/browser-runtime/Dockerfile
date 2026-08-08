FROM mcr.microsoft.com/playwright/python:v1.61.0-noble

WORKDIR /opt/rdc-browser

COPY requirements.txt /opt/rdc-browser/requirements.txt
RUN pip install --no-cache-dir -r /opt/rdc-browser/requirements.txt

COPY browser_runtime.py /opt/rdc-browser/browser_runtime.py

USER pwuser

ENTRYPOINT ["python", "/opt/rdc-browser/browser_runtime.py"]
