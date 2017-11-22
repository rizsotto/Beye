#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name='analyze-build',
    version='2.0.11',
    author='László Nagy',
    author_email='rizsotto@gmail.com',
    keywords=['Clang', 'static analyzer'],
    url='https://github.com/rizsotto/scan-build',
    license='LICENSE.txt',
    description='Clang-SA (static analyzer) wrapper.',
    long_description=open('README.rst').read(),
    zip_safe=False,
    install_requires=['typing'],
    packages=['libscanbuild'],
    package_data={
        'libscanbuild': [
            'resources/*'
        ]
    },
    entry_points={
        'console_scripts': [
            'analyze-build = libscanbuild.analyze:analyze_build'
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: University of Illinois/NCSA Open Source License",
        "Environment :: Console", "Operating System :: POSIX",
        "Operating System :: MacOS :: MacOS X",
        "Intended Audience :: Developers", "Programming Language :: C",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Compilers",
        "Topic :: Software Development :: Quality Assurance"
    ])
