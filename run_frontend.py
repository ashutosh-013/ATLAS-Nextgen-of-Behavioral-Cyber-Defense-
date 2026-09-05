"""
ATLAS Frontend Dashboard Runner

This script starts the Flask web application in web_app.py, hosting both the
interactive threat intelligence dashboard and the live BADNA analytics backend APIs,
then launches the web browser automatically.
"""

import webbrowser
import threading
import time
import sys
import os

# Import the Flask application from web_app
from web_app import app

PORT = 5000

def open_browser():
    # Wait for the Flask server to bind and start listening
    time.sleep(1.5)
    url = f"http://localhost:{PORT}/"
    print(f"\n[ATLAS] Unified Server active. Launching web browser to: {url}")
    webbrowser.open(url)

def main():
    # Set up thread to launch browser once server starts
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    print(f"================================================================================")
    print(f"ATLAS (Behavioral Cyber Threat Intelligence Platform) Unified Server")
    print(f"================================================================================")
    print(f"Starting Flask server on port {PORT}...")
    print(f"Press Ctrl+C to terminate.")
    
    try:
        # Run Flask application with multithreading enabled for SSE stream concurrency
        app.run(debug=False, host='0.0.0.0', port=PORT, threaded=True)
    except KeyboardInterrupt:
        print("\n[ATLAS] Shutting down unified server. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ATLAS] Unified Server failed to start: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
