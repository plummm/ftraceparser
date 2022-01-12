import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="ftracepaser",
    version="0.1.2",
    description="Parse ftrace report in a human readable format",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/plummm/ftracepaser",
    author="Xiaochen Zou",
    author_email="etenal@etenal.me",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    packages=["ftraceparser"],
    include_package_data=True,
    install_requires=[
        "requests>=2.26.0",
        "progressbar2==3.55.0", 
        "console",
    ],
    entry_points={
        "console_scripts": [
            "realpython=ftraceparser.__main__:main",
        ]
    },
)