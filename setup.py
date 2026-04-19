"""Setup configuration for aws-iam-privesc-finder."""
from setuptools import setup, find_packages
from pathlib import Path


readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""


setup(
    name="aws-iam-privesc-finder",
    version="1.0.0",
    description=(
        "Detect known IAM privilege escalation paths in AWS accounts "
        "for authorized penetration testing and defensive review."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="aws-iam-privesc-finder contributors",
    license="MIT",
    python_requires=">=3.10",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "rich>=13.7.0",
        "jinja2>=3.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-mock>=3.12.0",
            "moto>=5.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aws-privesc-finder=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
