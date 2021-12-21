from setuptools import setup

setup(
    name='create_cluster',
    version='0.1.0',
    py_modules=['create_cluster'],
    install_requires=[
        'Click',
    ],
    entry_points={
        'console_scripts': [
            'gop = create_cluster:cli',
        ],
    },
)