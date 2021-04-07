import sys

from setuptools import setup, find_packages

with open('requirements.txt') as requirements_file:
    requirements = requirements_file.read().splitlines()

project_name = 'dragoneye'

version = '0.0.1'

if "--version" in sys.argv:
    index = sys.argv.index('--version')
    version = sys.argv[index + 1]
    sys.argv.remove("--version")
    sys.argv.remove(version)

setup(
    name=project_name,
    version=version,
    description='Multi-cloud data scan tool',
    author='Indeni',
    packages=find_packages(include=[project_name, f'{project_name}.*']),
    install_requires=requirements,
    entry_points={
        'console_scripts': [f'{project_name}=dragoneye.scan:scan_cli']
    }
)