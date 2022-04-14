import setuptools
from datetime import datetime

current_version = datetime.utcnow().strftime("%Y.%m")

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name='fido-mds',
    version=current_version,
    url='https://github.com/Sunet/python-fido2-mds',
    license='BSD 3-Clause',
    author='Johan Lundberg',
    author_email='lundberg@sunet.se',
    description='fido2 metadata service in a package',
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
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
    python_requires=">=3.7, <4",
    install_requires=[
        "fido2",
        "pydantic",
        "cryptography",
        "pyOpenSSL",
    ],
    tests_requires=[
        "pytest",
    ],
)
