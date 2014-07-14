'''
VPNaaS setup

'''

from setuptools import setup, find_packages
import ez_setup

ez_setup.use_setuptools()

setup(
    name = "VPNaaS",
    version = "0.1",
    packages = find_packages(),
    
    install_requires = ['ncclient >= 0.1a',
                        'lxml > 3.0'
                        ],
    dependency_links = [
        "https://github.com/Juniper/ncclient/archive/master.zip"
    ]
)
