import os
import subprocess
import yaml
from time import sleep


def run_from_yaml(yaml_path, variables):
    with open(yaml_path, "r") as f:
        steps = yaml.safe_load(f)

    for step in steps:
        name = step.get("name", "Unnamed step")
        raw_cmd = step.get("command", "")

        # Podstaw zmienne {{Target}}, {{Output}}, itd.
        for var, val in variables.items():
            raw_cmd = raw_cmd.replace(var, val)

        print(f"[FLOW] {name}: {raw_cmd}")
        try:
            subprocess.run(raw_cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] Step failed: {name}")
            print(e)
            break
        sleep(0.3)
