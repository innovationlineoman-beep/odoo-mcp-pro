FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "mcp-server-odoo @ git+https://github.com/pantalytics/odoo-mcp-pro.git"

EXPOSE 8000

CMD ["python", "-m", "mcp_server_odoo", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
