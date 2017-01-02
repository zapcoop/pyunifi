#!/usr/bin/env python

from distutils.core import setup
import sys

if sys.version_info[0] == 2:
    from commands import getoutput
elif sys.version_info[0] == 3:
    from subprocess import getoutput


setup(name='pyunifi',
      version='1.3',
      description='API towards Ubiquity Networks UniFi controller',
      author='Caleb Dunn',
      author_email='finish.06@gmail.com',
      url='https://github.com/finish06/unifi-api',
      packages=['pyunifi'],
      scripts=['unifi-low-snr-reconnect', 'unifi-ls-clients', 'unifi-save-statistics', 'unifi-log-roaming'],
      classifiers=[],
     )
