ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-requests py3-websocket-client py3-paho-mqtt nmap nmap-scripts tzdata

WORKDIR /app
COPY app /app

CMD ["python3", "-u", "-m", "scanner"]
