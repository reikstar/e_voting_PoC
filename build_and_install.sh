#!/bin/bash

echo "Cleaning previous builds..."
rm -rf build/ dist/ *.egg-info

echo "Building the package..."
python3 setup.py sdist bdist_wheel

echo "Installing the package..."
pip install dist/evoting-1.0-py3-none-any.whl

echo "Build and installation complete."