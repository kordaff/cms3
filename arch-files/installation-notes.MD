#!/bin/bash

# Start to finish, install Arch, install all these packages, reconfigure httpd, configure cms3

# configure PostgreSQL

# as postgres:
# initdb -D /var/lib/postgres/data

# as root (since postgres shouldn't have sudo access, start as root, su - postgres as needed)
# sudo systemctl enable postgresql
# sudo systemctl start postgresql
# Possibly - change data/pg_hba.conf to allow other machines/vm's on LAN to access db
#          - also change the listen line to listen: '*'  # in that case   

# as postgres again:
# createuser cms3 
# createdb cms3 -O cms3

# just to get this git clone, requires openssh, git, grub after the first pacstrap.

# ----  servers and utils  ----
# sudo pacman -S dnsutils ntp base-devel apache postgresql mlocate wget pkgfile net-tools perl-datetime perl-dbd-pg perl-email-address perl-inc-latest perl-mime-lite perl-module-build perl-par-dist perl-readonly perl-test-pod perl-test-pod-coverage perl-yaml 

# 
# ---- perl modules and mod_perl from AUR (these get installed by a user acct with sudo access)
# ---- be sure to have gpg keys setup 
# 

# as that user:
# gpg --full-gen-key
# gpg --recv-key AB34BA0040E92ECE
# to get Apache's Steve Hay's key installed for the mod_perl module.

mkdir ~/Downloads

for i in mod_perl perl-apache-dbi perl-cgi-cookie perl-class-mix perl-crypt-eksblowfish perl-crypt-random-source perl-uri-escape-xs
  do
    /home/USERNAME/bin/acquire-aur.sh $i
    # you can also add ~/bin to PATH in .bash_profile
  done

#  I got real tired of finding the snapshot in the AUR section of wiki.archlinux.org, downloading
#    it manually to ungzip and untar.  Then cd'ing in and makepkg -si
#    Thus: the acquire-aur.sh script.
#  I was trying to get starman to install at the time, lots more prereq's for that...

# -----------------------------------------------------------------------------
# -- More notes to follow once I do this install one more time by cloning the - 
# -- git repo.  Had to massively fix store_page in cms3.pm this time.         -
# -----------------------------------------------------------------------------
