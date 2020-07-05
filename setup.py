from setuptools import setup


__version__ = None
with open('ppcswift/_version.py', 'r') as f:
    exec(f.read())


setup(
    name='pypicloud-swift',
    version=__version__,
    description='OpenStack Swift storage for PyPI Cloud',
    long_description=open("README.rst").read(),
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Environment :: OpenStack',
        'Environment :: Plugins',
        'Environment :: Web Environment',
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: System :: Systems Administration',
    ],
    license='MIT',
    author='Andrey Ulagashev',
    author_email='ulagashev.andrey@gmail.com',
    url='https://github.com/HDScorpio/pypicloud-swift',
    keywords='pypi package openstack swift object storage',
    platforms='any',
    install_requires=[
        'pypicloud >= 1.0.14',
        'python-swiftclient'
    ],
    python_requires='>=3.5',
    packages=['ppcswift']
)
