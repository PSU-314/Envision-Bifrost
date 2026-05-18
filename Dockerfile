FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    g++ cmake make libboost-all-dev libssl-dev \
    libcurl4-openssl-dev python3 git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy CMakeLists.txt first so dependency fetch is cached separately.
# This layer only re-runs if CMakeLists.txt changes, saving ~8 mins on rebuild.
COPY CMakeLists.txt ./
RUN cmake -S . -B build 2>&1 | grep -i "fetch\|clone\|download" || true

# Now copy full source and build
COPY include/ ./include/
COPY src/ ./src/
RUN cmake -S . -B build && cmake --build build --target Bifrost -j$(nproc)
RUN cp build/Bifrost ./bifrost-bin

# Copy the Python server
COPY bifrost_server.py .

ENV BIFROST_BIN=/app/bifrost-bin
ENV SECRET_KEY_PATH=/app/shared_secret.txt
# Set this in Railway Variables tab:
# LOGIN_SERVER_URL=https://your-login-server.up.railway.app/signup/

EXPOSE 8000
CMD ["python3", "bifrost_server.py"]
