FROM amazonlinux:latest
LABEL authors="sadamu"

# TBD
EXPOSE 8008

WORKDIR /usr/src/synapse
COPY . .

# initial setup
RUN dnf update -y
RUN dnf -y groupinstall "Development Tools"
RUN dnf install -y openssl-devel bzip2-devel libffi-devel zlib-devel libtiff-devel libjpeg-devel libzip-devel freetype-devel libwebp-devel libxml2-devel libxslt-devel libpq-devel  python3-virtualenv libffi-devel openssl-devel python3-devel  libicu-devel
RUN dnf install -y rust cargo
RUN dnf install -y postgresql15

# poetry setup
RUN curl -sSL https://install.python-poetry.org | python3
# Poetryのパスの設定
ENV PATH /root/.local/bin:$PATH

# install synapse
RUN git config --global --add safe.directory /usr/src/synapse
RUN poetry install --extras all
RUN find /usr/src/synapse/build -name "synapse_rust.abi3.so" -exec cp {} /usr/src/synapse/synapse \;
