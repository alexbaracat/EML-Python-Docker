# Use an official lightweight Python image
FROM python:3.12-slim

# Set working directory in the container
WORKDIR /app

# Install system deps (optional but often useful)
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency list and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose Flask default port
EXPOSE 5000

# Default command to run your app
CMD ["python", "app.py"]
