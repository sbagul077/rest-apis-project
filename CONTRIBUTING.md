# CONTRIBUTING

## How to run the Dockerfile locally


'''
docker run -dp 5000:5000 -w /app -v "$(pwd):/app" teclado-site-flask sh -c "flask-run"
'''