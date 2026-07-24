"""Local dev entrypoint: `python run.py`.

Production uses gunicorn against `wsgi:app` instead (see Dockerfile) --
Flask's built-in server here is single-threaded and not meant to survive
real traffic.
"""

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(debug=app.config.get("DEBUG", False))
