FROM node:20-alpine

# Timezone Brasil (evita bugs de horário no servidor UTC)
ENV TZ=America/Sao_Paulo
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/America/Sao_Paulo /etc/localtime && \
    echo "America/Sao_Paulo" > /etc/timezone && \
    apk del tzdata

WORKDIR /app

# Instala dependências
COPY package*.json ./
RUN npm install --omit=dev

# Copia o resto do projeto
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
