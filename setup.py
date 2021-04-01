from setuptools import setup, find_packages

with open('requirements.txt') as requirements_file:
    requirements = requirements_file.read().splitlines()

project_name = 'dragoneye'

setup(
    name=project_name,
    version='0.0.1',
    description='Multi-cloud data collect tool',
    author='Indeni',
    packages=find_packages(include=[project_name, f'{project_name}.*']),
    install_requires=requirements,
    entry_points={
        'console_scripts': [f'{project_name}=dragoneye.cli:cli']
    }
)