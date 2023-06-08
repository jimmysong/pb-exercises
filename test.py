from os import chdir
from subprocess import call


for session in range(9):
    chdir("session{}".format(session))
    call("pytest --disable-warnings *.py", shell=True)
    chdir("complete")
    call("pytest --disable-warnings *.py", shell=True)
    chdir("../..")
