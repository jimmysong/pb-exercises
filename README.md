# Pre-Requisites

Install python 3.5 or above on your machine:

Windows: https://www.python.org/ftp/python/3.6.2/python-3.6.2-amd64.exe
Mac OS X: https://www.python.org/ftp/python/3.6.2/python-3.6.2-macosx10.6.pkg
Linux: see your distro docs (ubuntu: `$ sudo apt-get install python3`)

Install pip:

Download this script: https://bootstrap.pypa.io/get-pip.py

Run

    $ python3 get-pip.py

Install git:

https://git-scm.com/downloads

Install virtualenv:

    $ pip install virtualenv

# Download pb-exercises requirements

    $ git clone https://github.com/jimmysong/pb-exercises
    $ cd pb-exercises
    $ virtualenv -p python3 .venv

Linux/OSX:

    $ . .venv/bin/activate
    (.venv) $ pip install -r requirements.txt

Windows:
    > .venv\Scripts\activate.bat
    > 

# Run jupyter notebook

    (.venv) $ jupyter notebook

# Run through session 0

Session 0 will help you get acquainted with some of the tools before you get to the Programming Blockchain Seminar