FROM python:3.12-slim-bookworm AS liboqs-builder

ARG LIBOQS_VERSION=0.16.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       ca-certificates \
       cmake \
       git \
       libssl-dev \
       ninja-build \
    && rm -rf /var/lib/apt/lists/*

RUN git clone \
      --branch "${LIBOQS_VERSION}" \
      --depth 1 \
      https://github.com/open-quantum-safe/liboqs.git \
      /src/liboqs

RUN cmake \
      -S /src/liboqs \
      -B /src/liboqs/build \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_ALGS_ENABLED=STD \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=ON \
    && cmake --build /src/liboqs/build --parallel \
    && cmake --install /src/liboqs/build

FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    OQS_INSTALL_PATH=/opt/liboqs \
    LD_LIBRARY_PATH=/opt/liboqs/lib

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       libgomp1 \
       libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=liboqs-builder /opt/liboqs /opt/liboqs

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY shared /app/shared
COPY services /app/services
COPY scripts /app/scripts
COPY tests /app/tests
