# Pre-Requisites

Install python 3.5 or above on your machine:

 * Windows: https://www.python.org/ftp/python/3.6.2/python-3.6.2-amd64.exe
 * Mac OS X: https://www.python.org/ftp/python/3.6.2/python-3.6.2-macosx10.6.pkg
 * Linux: see your distro docs

Install pip:

Download this script: https://bootstrap.pypa.io/get-pip.py

Run (you may need to specify python3 if you also have python2 installed)

    $ python get-pip.py

Install git:

https://git-scm.com/downloads

Install libbitcoin-explorer:

Windows - download https://github.com/libbitcoin/libbitcoin-explorer/releases/download/v3.2.0/bx-windows-x64-icu.exe and `move bx-windows-x64-icu.exe bx.exe`

Mac - download https://github.com/libbitcoin/libbitcoin-explorer/releases/download/v3.2.0/bx-osx-x64-qrcode and `sudo mv bx-osx-x64-qrcode /usr/local/bin/bx` and `sudo chmod +x /usr/local/bin/bx`

Linux - download https://github.com/libbitcoin/libbitcoin-explorer/releases/download/v3.2.0/bx-linux-x64-qrcode and `sudo mv bx-osx-x64-qrcode /usr/local/bin/bx` and `sudo chmod +x /usr/local/bin/bx`

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
