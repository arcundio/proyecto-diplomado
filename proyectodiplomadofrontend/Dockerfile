# Dockerfile para React
FROM node:18-alpine

WORKDIR /app

# Instalar dependencias
COPY package*.json ./
RUN npm install

# Copiar el código de la aplicación
COPY . .

# Construir la aplicación de React
RUN npm run build

# Servir con un servidor estático como 'serve'
RUN npm install -g serve

# Exponer el puerto para la app
EXPOSE 3000

# Comando para iniciar la aplicación
CMD ["serve", "-s", "build"]
