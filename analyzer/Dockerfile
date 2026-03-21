FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the analysis script
COPY generate_ads_index.py .

# Create an internal directory for the output files
RUN mkdir -p /app/reports

CMD ["python", "generate_ads_index.py"]