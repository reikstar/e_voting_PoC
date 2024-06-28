#!/bin/bash

# Delete all .json files in the current directory
if ls *.json 1> /dev/null 2>&1; then

    rm *.json
    echo "All .json files have been deleted from the current directory."
else
    echo "No .json files found in the current directory."
fi