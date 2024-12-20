from setuptools import setup, find_packages

setup(
    name="pyMLS",
    version="0.1.0",
    author="ZM",
    author_email="ZM@example.com",
    description="RFC 9420 (Message Layer Security) Python Implementation",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/code-zm/pyMLS",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.4.8",
        "jsonschema>=3.2.0"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)

