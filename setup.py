from setuptools import setup, find_namespace_packages

with open('requirements.txt') as requirements_file:
    requirements = requirements_file.read().splitlines()

setup(
    name='dragoneye',
    version='0.0.1',
    descriptioon='Multi-cloud data collect tool',
    author='Indeni',
    packages=['collectors.azure_collect_tool'],
    install_requires=requirements,
    entry_points={
        'console_scripts': ['dragoneye=main:cli']
    }
)