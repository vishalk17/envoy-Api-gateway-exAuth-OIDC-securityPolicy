# Use official Nginx image
FROM nginx:alpine

# Install tzdata and set timezone (no CA certificates)
RUN apk add --no-cache tzdata curl
ENV TZ=Asia/Kolkata
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Create log directory and set permissions
RUN mkdir -p /var/log/nginx

# Copy custom nginx configuration
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf

# Copy HTML pages
COPY nginx/index.html /usr/share/nginx/html/
COPY nginx/backend_info.html /usr/share/nginx/html/backend_info.html

# Expose port 80
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD curl -f http://localhost/ || exit 1

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]