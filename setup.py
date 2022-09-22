#!/usr/bin/env python3
import os
import subprocess
from datetime import date

from setuptools import setup, find_packages

local_path = os.path.dirname(__file__)
try:
    with open(os.path.join(local_path, "README.md"), "r") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = ''


def get_version(app):
    version = date.today().strftime('%Y-%m')
    git_tag = "0.0"
    git_commits = "0"
    suffix = "dev"
    branch = 'develop'
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"]
        ).rstrip().decode('utf8')
        git_describe = subprocess.check_output(
            ["git", "describe", "--long", "tags"]
        ).rstrip().decode('utf8')
        if 'fatal' not in git_describe:
            git_tag = git_describe.split('-')[0]
            git_commits = git_describe.split('-')[1]
        else:
            git_tag = branch
            git_commits = -1
        if branch == 'master':
            suffix = ''
        else:
            suffix = 'dev'
        print(branch, git_tag, git_commits, suffix)
        if git_commits == -1:
            version = branch
        else:
            version = f'{git_tag}.{git_commits}{suffix}'
    except (subprocess.CalledProcessError, OSError) as e:
        print('git not installed', e)
    try:
        fp = open(os.path.join(local_path, app, 'version.py'), 'w')
        if git_commits == -1:
            fp.write(f"api_version = '{branch}'\n")
        else:
            fp.write(
                f"api_version = '{git_tag}.{git_commits}.{suffix}'\n")
        fp.close()
    except IOError:
        print(f'ERROR opening {app}/__version__.py', os.curdir)
    return version


module = 'kl_authentication'

setup(
    name='kl-auth-module',
    description='Kairnial authentication module for Python',
    python_requires='>3.8.0',
    version=get_version(module),
    author='Frédéric MEUROU',
    author_email='frederic.meurou@thinkproject.com',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://apiv3.kairnial.com/',
    install_requires=[
        "Django>=4.1",
        "django-extensions~=3.2",
        "djangorestframework~=3.14",
        "drf-spectacular~=0.24",
        "requests~=2.28.0",
    ],
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Environment :: Web Environment",
        "Development Status :: 5 - Production/Stable",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy"
    ],
    py_modules=[
        'kl_authentication'
    ],
)
