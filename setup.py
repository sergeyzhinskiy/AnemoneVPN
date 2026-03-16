from setuptools import setup, find_packages

setup(
    name="anemone",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.8.0",
        "cryptography>=3.4.0",
        "numpy>=1.19.0",
        "scikit-learn>=0.24.0",
        "joblib>=1.0.0",
        "aiortc>=1.3.0",
        "aioquic>=0.9.0",
        "websockets>=10.0",
        "nfstream>=6.0.0",
        "certifi>=2020.12.0",
        "pyyaml>=5.4.0",
    ],
    entry_points={
        "console_scripts": [
            "anemone=anemone.__main__:main",
        ],
    },
    python_requires=">=3.8",
    author="Anemone Team",
    description="Adaptive VPN protocol for DPI evasion",
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
)
