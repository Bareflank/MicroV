#!python -u

import os, sys
import shutil
import subprocess
import re

def shell(command, dir = '.'):
    print("in '%s' execute '%s'" % (dir, ' '.join(command)))
    sys.stdout.flush()

    sub = subprocess.Popen(' '.join(command), cwd=dir,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)

    for line in sub.stdout:
        print(line.decode(sys.getdefaultencoding()).rstrip())

    sub.wait()

    return sub.returncode

def get_repo(url, working):
    shell(['git', 'clone', '--no-checkout', url, working])

def get_branch(tag, working):
    shell(['git', 'checkout', '-b', 'tmp', tag], working)

def put_branch(working):
    shell(['git', 'checkout', 'master'], working)
    shell(['git', 'branch', '-d', 'tmp'], working)

def copy_file(working, dir, name):
    try:
        os.makedirs('include\\xen\\%s' % dir)
    except OSError:
        None

    src = open('%s\\xen\\include\\%s\\%s' % (working, dir, name), 'r')
    dst = open('include\\xen\\%s\\%s' % (dir, name), 'w', newline='\n')

    print(name)

    for line in src:
        line = re.sub(' unsigned long', ' ULONG_PTR', line)
        line = re.sub('\(unsigned long', '(ULONG_PTR', line)
        line = re.sub(' long', ' LONG_PTR', line)
        line = re.sub('\(long', '(LONG_PTR', line)
        dst.write(line)

    dst.close()
    src.close()

if __name__ == '__main__':
    tag = sys.argv[1]
    working = sys.argv[2]

    get_repo('git://xenbits.xen.org/xen.git', working)
    get_branch(tag, working)

    shell(['git', 'rm', '-r', '-f', 'xen'], 'include')

    copy_file(working, 'public', 'xen.h')
    copy_file(working, 'public', 'xen-compat.h')

    copy_file(working, 'public\\arch-x86', 'xen.h')
    copy_file(working, 'public\\arch-x86', 'xen-x86_32.h')
    copy_file(working, 'public\\arch-x86', 'xen-x86_64.h')

    copy_file(working, 'public\\hvm', 'hvm_info_table.h')

    put_branch(working)

    shell(['git', 'add', 'xen'], 'include')
