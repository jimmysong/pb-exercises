from subprocess import call

import sys


filename = sys.argv[1]
parts = filename.split('/')
start = int(parts[0][-1])
print(start)

if parts[1] == 'complete':
    start += 1
    patch_file = parts[2]
    skip = False
else:
    patch_file = parts[1]
    skip = True

to_patch = patch_file.split('.')[0] + '.py'

for session in range(start, 9):
    if skip:
        skip = False
    else:
        call('patch -p1 session{}/{} < {}'.format(session, to_patch, filename), shell=True)
    call('patch -p1 session{}/complete/{} < {}'.format(session, to_patch, filename), shell=True)
