# Usar imagen oficial de Node.js con Alpine Linux para un tamaño reducido
FROM node:18-alpine

# Instalar nginx para servir la aplicación
RUN apk add --no-cache nginx

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar archivos de dependencias
COPY package*.json ./

# Instalar dependencias de desarrollo para el build
RUN npm ci

# Instalar terser para minificación en producción (requerido por Vite v6)
RUN npm install terser --save-dev

# Copiar el código fuente
COPY . .

# Construir la aplicación
RUN npm run build

# Configurar nginx para servir la aplicación
COPY nginx.conf /etc/nginx/nginx.conf

# Exponer el puerto 80
EXPOSE 80

# Comando para ejecutar nginx
CMD ["nginx", "-g", "daemon off;"]