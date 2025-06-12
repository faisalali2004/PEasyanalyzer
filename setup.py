from setuptools import setup, find_packages

setup(
    name="PEasyAnalyzer",
    version="1.0",
    description="Beginner-friendly malware static analysis tool for PE files",
    author="Your Name",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "pefile",
        "yara-python",
    ],
    entry_points={
        'gui_scripts': [
            'peasyanalyzer = main:run_gui',
        ],
    },
)
