import os
import json

def load_lines(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data, file_path):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def ensure_output_dir(path):
    os.makedirs(path, exist_ok=True)

def load_domains(path):
    """
    Loads domains from a .txt file, one per line.
    Ignores empty lines and comments (#).
    """
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def dedupe_paths(paths):
    """
    Removes duplicates and normalizes paths.
    """
    return list(set(os.path.normpath(p.strip()) for p in paths if p.strip()))
