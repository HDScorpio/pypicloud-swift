from setuptools import setup


setup(
    name='pypicloud-swift',
    version='0.1.2',
    description='OpenStack Swift storage for PyPI Cloud',
    long_description=open("README.rst").read(),
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
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
        'pypicloud',
        'python-swiftclient'
    ],
    packages=['ppcswift']
)
