import shutil
import subprocess


# copy all the ipynb notebooks
for i in range(8):
    current = 'session{}'.format(i)
    with open('{}.ipynb'.format(current), 'wb') as f:
        contents = subprocess.check_output(['git', 'show', 'master:{}/complete/{}.ipynb'.format(current, current)])
        f.write(contents)
    
# copy all the stuff from session7 complete
output = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', 'master']).decode('ascii')

for filename in output.split():
    if filename.startswith('session7/complete') and filename.endswith('.py'):
        print(filename)
        final_part = filename.split('/')[-1]
        with open(final_part, 'wb') as f:
            contents = subprocess.check_output(['git', 'show', 'master:{}'.format(filename)])
            f.write(contents)
