#!/bin/bash

echo "Installing Sakizuke."

# List of required packages
packagesList = "libssl-dev libcurl4-openssl-dev libcmocka-dev"

# Install packages
apt update
apt install -y $packagesList
