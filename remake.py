import shutil
import subprocess


for i in range(1,8):
    current = 'session{}'.format(i)
    output = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', current]).decode('ascii')
    for filename in output.split():
        if filename.endswith(('md','py','ipynb')):
            if filename.endswith(('md','ipynb')) \
               and not filename.startswith(current):
                continue
            with open('{}/{}'.format(current, filename), 'wb') as f:
                contents = subprocess.check_output(['git', 'show', '{}:{}'.format(current, filename)])
                f.write(contents)
    output = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', '{}-complete'.format(current)]).decode('ascii')
    for filename in output.split():
        if filename.endswith(('md','py','ipynb')):
            if filename.endswith(('md','ipynb')) \
               and not filename.startswith(current):
                continue
            with open('{}/complete/{}'.format(current, filename), 'wb') as f:
                contents = subprocess.check_output(['git', 'show', '{}-complete:{}'.format(current, filename)])
                f.write(contents)
    
                      
