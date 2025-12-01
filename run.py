# run.py

from app import create_app

app = create_app()

print("App object created")

if __name__ == '__main__':
    print("Entered __main__ block")
    try:
        app.run(debug=True, host="127.0.0.1", port=5000)
        print("🔥 Flask server is running")
    except Exception as e:
        print(f"❌ Flask failed to start: {e}")
else:
    print(" __name__ is not '__main__', Flask won't run")

