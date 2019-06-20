import re
import os.path
import sys

from setuptools import setup, find_packages

package_name = 'py3rijndael'
py_version = sys.version_info[:2]

# reading package's version
with open(os.path.join(os.path.dirname(__file__), package_name, '__init__.py')) as v_file:
    package_version = re.compile(r".*__version__ = '(.*?)'", re.S).match(v_file.read()).group(1)

setup(
    name=package_name,
    version=package_version,
    author='Mahdi Ghanea.g',
    description='Rijndael algorithm library for Python3.',
    long_description=open('README.rst').read(),
    url='https://github.com/meyt/py3rijndael',
    packages=find_packages(),
    license='MIT License',
    classifiers=[
        'Environment :: Console',
        'Topic :: Security :: Cryptography',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
