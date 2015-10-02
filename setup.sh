#!/bin/bash
#make sure to install Veil and SMBExec from the THP 2 Setup Phase first
pip install termcolor
wget thehackerplaybook.com/Download/winworder.zip
unzip winworder.zip
cp -R ./usr/share/pyinstaller /opt/pyinstaller-2.0
