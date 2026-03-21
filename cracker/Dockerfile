# Keep the 12.8.0 / Ubuntu 24.04 base
FROM nvidia/cuda:12.8.0-base-ubuntu24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Put pocl-opencl-icd BACK in, remove intel-opencl-icd
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3 \
    python3-pip \
    pocl-opencl-icd \
    clinfo \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && cd /opt \
    && git clone https://github.com/hashcat/hashcat.git \
    && cd hashcat \
    && make \
    && ln -s /opt/hashcat/hashcat /usr/local/bin/hashcat

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .
CMD ["python3", "cracker_service.py"]