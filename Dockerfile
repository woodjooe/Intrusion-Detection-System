FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install the required Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app files to the container
COPY . .

# Expose the port that the app will listen on
EXPOSE 8501

# Start the Streamlit app when the container starts
CMD ["streamlit", "run", "--server.port", "8501", "server.py"]
