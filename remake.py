import shutil
import subprocess


for i in range(8):
    current = 'session{}'.format(i)
    output = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', current]).decode('ascii')
    for filename in output.split():
        if filename.endswith(('py','ipynb')):
            if filename.endswith('ipynb') \
               and not filename.startswith(current):
                continue
            with open('{}/{}'.format(current, filename), 'wb') as f:
                contents = subprocess.check_output(['git', 'show', '{}:{}'.format(current, filename)])
                f.write(contents)
    output = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', '{}-complete'.format(current)]).decode('ascii')
    for filename in output.split():
        if filename.endswith(('py','ipynb')):
            if filename.endswith('ipynb') \
               and not filename.startswith(current):
                continue
            with open('{}/complete/{}'.format(current, filename), 'wb') as f:
                contents = subprocess.check_output(['git', 'show', '{}-complete:{}'.format(current, filename)])
                f.write(contents)
    
                      
