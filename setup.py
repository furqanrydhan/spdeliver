#!/usr/bin/env python
# -*- coding: utf-8 -*-

import setuptools
 
def setup():
    setuptools.setup(
        name='spdeliver',
        version='0.1',
        description='StylePage tools: Python message delivery',
        author='mattbornski',
        url='http://github.com/stylepage/spdeliver',
        package_dir={'': 'src'},
        py_modules=[
            'spdeliver',
        ],
        install_requires=[
            'git+https://github.com/facebook/python-sdk.git#egg=facebook-python-sdk',
            'python-twitter',
            'oauth2',
            'gdata',
            'APNSWrapper',
        ],
    )

if __name__ == '__main__':
    setup()