FROM node:20-alpine

WORKDIR /app

# Instala dependências
COPY package*.json ./
RUN npm install --omit=dev

# Copia o resto do projeto
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
