#!/bin/bash

echo "getting $1"

cd ~/Downloads
wget https://aur.archlinux.org/cgit/aur.git/snapshot/$1.tar.gz
gunzip $1.tar.gz
tar -xvf $1.tar
cd $1
makepkg -si
