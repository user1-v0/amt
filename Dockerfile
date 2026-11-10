FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    NONINTERACTIVE=1 \
    HOMEBREW_NO_AUTO_UPDATE=1 \
    HOMEBREW_NO_ANALYTICS=1 \
    HOME=/home/linuxbrew \
    PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:/app/.venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates curl file git procps unzip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash linuxbrew \
    && mkdir -p /home/linuxbrew/.linuxbrew /app \
    && chown -R linuxbrew:linuxbrew /home/linuxbrew /app

USER linuxbrew

RUN curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash

RUN brew install radare2 python@3.13 uv \
    && ln -sfn "$(brew --prefix python@3.13)/bin/python3.13" "$(brew --prefix)/bin/python3" \
    && ln -sfn "$(brew --prefix python@3.13)/bin/python3.13" "$(brew --prefix)/bin/python" \
    && r2pm -U \
    && r2pm -bci r2ghidra \
    && r2 -qc 'pdg?' - | grep -i pdg

RUN printf '%s\n' 'int JNI_OnLoad(void){return 65542;}' > /tmp/jni.c \
    && gcc -shared -fPIC -o /tmp/libjni.so /tmp/jni.c \
    && r2 -e scr.color=0 -qc 'aaa; pdg @ sym.JNI_OnLoad' /tmp/libjni.so | tee /tmp/pdg.out \
    && grep -E 'JNI_OnLoad|return' /tmp/pdg.out

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --chown=linuxbrew:linuxbrew pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project \
        --python "$(brew --prefix python@3.13)/bin/python3.13"

COPY --chown=linuxbrew:linuxbrew agent.py pipeline.py schemas.py ./
COPY --chown=linuxbrew:linuxbrew api ./api
COPY --chown=linuxbrew:linuxbrew agents ./agents
COPY --chown=linuxbrew:linuxbrew tools ./tools
COPY --chown=linuxbrew:linuxbrew utils ./utils

EXPOSE 8000

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
