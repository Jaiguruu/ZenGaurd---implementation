# Use Python 3.9 slim variant which includes core compilation libraries
# but cuts out bulk OS bloat to ensure a small container footprint.
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Ensure standard output streams bypass Docker buffering for real-time logs
ENV PYTHONUNBUFFERED=1

# Install requirements first to cache the layer against static code modifications
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire UEBA module contents into the container
# This firmly locks the current model.joblib and scaler.joblib versions inside
COPY . .

# Expose port 8000 for network bridging outside the container
EXPOSE 8000

# Execute FastAPI via Uvicorn. 
# 0.0.0.0 binding is entirely critical; retaining 127.0.0.1 drops all inbound container traffic.
CMD ["uvicorn", "model_server:app", "--host", "0.0.0.0", "--port", "8000"]
