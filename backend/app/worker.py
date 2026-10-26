"""Background worker entry point. Model tasks can be moved here when a broker is configured."""
import time

if __name__ == "__main__":
    while True:
        time.sleep(60)
