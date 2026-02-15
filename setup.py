"""Package setup for CryptoGuard."""

from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="cryptoguard",
    version="1.0.0",
    author="Taofik Bishi",
    description="A cryptographic security toolkit for file encryption, hashing, and password analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/taofikbishi/cryptoguard",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cryptoguard=cryptoguard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Typing :: Typed",
    ],
    keywords="cryptography encryption hashing password security",
)
