"""
Penterous setup.py — allows: pip install -e .
"""
from setuptools import setup, find_packages

with open('requirements.txt') as f:
    install_requires = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith('#')
    ]

setup(
    name='penterous',
    version='1.0.0',
    author='p3nt3r0us',
    description='Automated CTF Binary Exploitation Framework',
    long_description=open('README.md').read() if __import__('os').path.exists('README.md') else '',
    license='MIT',
    python_requires='>=3.11',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'penterous=penterous:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Topic :: Security',
        'Topic :: Education',
    ],
)
