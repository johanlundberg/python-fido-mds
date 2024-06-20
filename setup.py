import setuptools
from datetime import datetime

# Fixed version will help for reproducible builds
current_version = "2023.3"

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name='fido-mds',
    version=current_version,
    url='https://github.com/SUNET/python-fido-mds',
    license='BSD 3-Clause',
    author='Johan Lundberg',
    author_email='lundberg@sunet.se',
    description='FIDO Alliance Metadata Service in a package',
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
        "OSI Approved:: BSD License",
        "MacOS:: MacOS X",
        "Microsoft:: Windows",
        "POSIX",
        "POSIX:: BSD",
        "POSIX:: Linux",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    package_data={
        "fido_mds": ["data/metadata.json", "data/apple_webauthn_root_ca.pem"],
    },
    python_requires=">=3.8, <4",
    install_requires=[
        "fido2>=1.0.0",
        "pydantic",
        "cryptography",
        "pyOpenSSL",
    ],
    tests_requires=[
        "pytest",
    ],
)
