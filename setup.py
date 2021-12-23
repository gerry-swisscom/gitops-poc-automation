from setuptools import setup

setup(
    name='create_cluster',
    version='0.1.0',
    py_modules=['create_cluster'],
    install_requires=[
        'Click', 'boto3', 'pyyaml'
    ],
    entry_points={
        'console_scripts': [
            'gop = create_cluster:cli',
        ],
    },
)