#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os.path
import setuptools
 
def setup():
    with open(os.path.join('src', 'spdeliver.py'), 'r') as f:
        for line in f.readlines():
            if 'version' in line:
                try:
                    exec(line)
                    assert(isinstance(version, basestring))
                    break
                except (SyntaxError, AssertionError, NameError):
                    pass
    try:
        assert(isinstance(version, basestring))
    except (AssertionError, NameError):
        version = 'unknown'
    
    setuptools.setup(
        name='spdeliver',
        version=version,
        description='StylePage tools: Python message delivery',
        author='mattbornski',
        url='http://github.com/stylepage/spdeliver',
        package_dir={'': 'src'},
        py_modules=[
            'spdeliver',
        ],
        install_requires=[
            'facebook-python-sdk',
            'python-twitter',
            'oauth2',
            'gdata',
            'twilio'
        ],
        dependency_links=[
            'http://github.com/facebook/python-sdk/tarball/master#egg=facebook-python-sdk',
            'https://github.com/twilio/twilio-python.git'
        ],
    )

if __name__ == '__main__':
    setup()