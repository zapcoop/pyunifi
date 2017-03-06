#!/usr/bin/env python

from distutils.core import setup

setup(name='pyunifi',
      version='2.0',
      description='API towards Ubiquity Networks UniFi controller',
      author='Caleb Dunn',
      author_email='finish.06@gmail.com',
      url='https://github.com/finish06/unifi-api',
      packages=['pyunifi'],
      scripts=['unifi-low-snr-reconnect', 'unifi-ls-clients', 'unifi-save-statistics', 'unifi-log-roaming'],
      classifiers=[],
      install_requires=['requests'],
     )
