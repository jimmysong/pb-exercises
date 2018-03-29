import subprocess
import sys

prev_branch = sys.argv[1]

while prev_branch != 's0':
    if prev_branch.endswith('-c'):
        current_branch = prev_branch[:2]
    else:
        i = int(prev_branch[1]) - 1
        current_branch = 's{}-c'.format(i)
    subprocess.check_output(['git', 'checkout', current_branch])
    to_cherry_pick = subprocess.check_output(['git', 'log', '-1', '--pretty=%H']).decode('ascii')[:-1]
    subprocess.check_output(['git', 'reset', '--hard', prev_branch])
    subprocess.check_output(['git', 'cherry-pick', to_cherry_pick])
    subprocess.check_output(['git', 'push', 'origin', '+HEAD'])
    prev_branch = current_branch
