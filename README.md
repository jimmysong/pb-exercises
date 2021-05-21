# Pre-Requisites

Install python 3.8 or above on your machine:

 * Windows: https://www.python.org/downloads/release/python-395/
 * Mac OS X: https://www.python.org/downloads/release/python-395/
 * Linux: see your distro docs (on Debian/Ubuntu `sudo apt get install python3` should work)

Install pip:

Download this script: https://bootstrap.pypa.io/get-pip.py

Run (you may need to specify python3 if you also have python2 installed)

    $ python get-pip.py

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
    > pip install -r requirements.txt

# Run jupyter notebook

    (.venv) $ jupyter notebook
