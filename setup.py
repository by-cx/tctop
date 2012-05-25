import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "tctop",
    version = "0.1",
    author = "Adam Strauch",
    author_email = "cx@initd.cz",
    description = ("Stats tool for tc"),
    license = "BSD",
    keywords = "tc, shaper, shaping, hfsc, htb",
    url = "",
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    long_description="Stats tool for tc. It's designed to my network and I cannot say if it will be fine for you",#read('README'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
    install_requires=[
        #"termcolor",
        ],
    entry_points="""
    [console_scripts]
    tctop = tctop.tctop:main
    """
)
