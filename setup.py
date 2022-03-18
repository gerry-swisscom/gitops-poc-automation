from setuptools import setup

setup(
    name='create_cluster',
    version='0.1.1',
    py_modules=['create_cluster'],
    install_requires=[
        'Click', 'boto3', 'pyyaml'
    ],
    entry_points={
        'console_scripts': [
            'tdectl = create_cluster:cli',
        ],
    },
)