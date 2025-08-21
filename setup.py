from setuptools import find_packages, setup

setup(
    name="reconcli",
    version="0.3.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "reconcli = reconcli.main:cli",
        ],
    },
)
