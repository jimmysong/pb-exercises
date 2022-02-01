import shutil
import subprocess


for i in range(8):
    current = "session{}".format(i)
    branch = "s{}".format(i)
    output = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", current]
    ).decode("ascii")
    for filename in output.split():
        if filename.endswith(("py", "ipynb")) and filename != "redo.py":
            if filename.endswith("ipynb") and not filename.startswith(current):
                continue
            with open("{}/{}".format(current, filename), "wb") as f:
                contents = subprocess.check_output(
                    ["git", "show", "{}:{}".format(branch, filename)]
                )
                f.write(contents)
    output = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", "{}-c".format(branch)]
    ).decode("ascii")
    for filename in output.split():
        if filename.endswith(("py", "ipynb")) and filename != "redo.py":
            if filename.endswith("ipynb") and not filename.startswith(current):
                continue
            with open("{}/complete/{}".format(current, filename), "wb") as f:
                contents = subprocess.check_output(
                    ["git", "show", "{}-c:{}".format(branch, filename)]
                )
                f.write(contents)
