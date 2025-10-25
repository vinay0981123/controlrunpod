# Base image (CUDA 12.3 + cuDNN 9 runtime)
FROM nvidia/cuda:12.3.2-cudnn9-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# Cache dirs for HF/Torch (optional but useful)
ENV HF_HOME=/workspace/.cache/huggingface
ENV TRANSFORMERS_CACHE=/workspace/.cache/huggingface/transformers
ENV HUGGINGFACE_HUB_CACHE=/workspace/.cache/huggingface/hub
ENV TORCH_HOME=/workspace/.cache/torch

# Install Python + runtime deps (single layer)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.10 python3.10-venv python3-pip \
    sudo openssh-server curl git ca-certificates ffmpeg wget \
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libncursesw5-dev libffi-dev liblzma-dev libxml2-dev libxmlsec1-dev \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3.10 /usr/bin/python3 \
    && ln -sf /usr/bin/pip3 /usr/bin/pip

# Create cache dirs (so HF/Torch have writable paths when volume mounts)
RUN mkdir -p /workspace/.cache/huggingface /workspace/.cache/torch /workspace/hearmefinal/logs

# SSH setup (root password; you should use keys in production)
RUN mkdir /var/run/sshd \
    && echo 'root:root' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' /etc/pam.d/sshd

# Add a safer non-root user (optional)
RUN useradd -m -s /bin/bash user && echo 'user:user' | chpasswd && adduser user sudo || true

# Copy entrypoint and make executable
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Expose ssh port
EXPOSE 22

# Entrypoint will start sshd, wait for /workspace/hearmefinal and run ./run.sh inside venv
ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
