from setuptools import setup
from pathlib import Path

readme = Path(__file__).with_name("README.rst").read_text()

setup(
    name="cert_expiry_check",
    version="0.1",
    description="Send certificate expiry notification "
                "to vpsFree.cz IPv6 tunnels users",
    long_description=readme,
    long_description_content_type="text/x-rst",
    url="https://github.com/oskar456/check_cert_expiry",
    author="Ondřej Caletka",
    author_email="ondrej@caletka.cz",
    license="MIT",
    py_modules=["cert_expiry_check"],
    install_requires=[
        'PyOpenSSL',
        'PyYAML',
        'click',
    ],
    setup_requires=["pytest-runner"],
    python_requires=">=3.5",
    tests_require=["pytest"],
    entry_points={
        "console_scripts": [
            "cert_expiry_check = cert_expiry_check:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: System :: Systems Administration",
    ],

)
