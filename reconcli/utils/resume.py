import os
import json


def load_resume(output_dir):
    path = os.path.join(output_dir, "resume.cfg")
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def save_resume_state(output_dir, state):
    path = os.path.join(output_dir, "resume.cfg")
    with open(path, "w") as f:
        json.dump(state, f, indent=2)


def clear_resume(output_dir):
    path = os.path.join(output_dir, "resume.cfg")
    if os.path.exists(path):
        os.remove(path)
