module.exports = {
  apps: [
    {
      name: "auto-deploy-bot",
      script: "gunicorn",
      // Arguments: Bind to port 7070, use 4 workers, run the 'app' object from 'main.py'
      args: "--bind 0.0.0.0:7070 --workers 4 --access-logfile - --error-logfile - automate:app",
      interpreter: "python3", // Or the path to your venv python if you use one
      cwd: "/root/path/to/your/script/folder", // <--- UPDATE THIS PATH
      env: {
        // You can verify env vars here if needed, but your script loads .env automatically
      }
    }
  ]
};