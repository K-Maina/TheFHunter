"""
# Author : Khalid Maina.
# Date : 01/08/2021.

....................................
script that downloads python modules
....................................
"""
import subprocess
modules = {'termcolor', 'pyzipper', 'pyAesCrypt', 'pandas'}
for module in modules:
    subprocess.call('pip3 install {}'.format(module), shell = True)
print('Done')
