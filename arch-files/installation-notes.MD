#!/bin/bash

# Start to finish, install Arch, install all these packages, reconfigure httpd, configure cms3
# fix the seemly inevitable errors everywhere.   2 hours, third Arch install of cms3

# ----  servers and utils  ----
# sudo pacman -S dnsutils ntp base-devel openssh apache postgresql mlocate wget pkgfile net-tools

# ----  perl modules in core/extra/etc repos ----
# sudo pacman -S perl-datetime perl-dbd-pg perl-email-address perl-inc-latest perl-mime-lite perl-module-build perl-par-dist perl-readonly perl-test-pod perl-test-pod-coverage perl-yaml 

# 
# ---- perl modules and mod_perl from AUR (these get installed by a user acct with sudo access)
# ---- be sure to have gpg keys setup 
# 

# as that user:

mkdir ~/Downloads

for i in `mod_perl perl-apache-dbi perl-cgi-cookie perl-class-mix perl-crypt-eksblowfish perl-crypt-random-source perl-uri-escape-xs` 
  do
    /home/USERNAME/bin/acquire-aur.sh $i
    # you can also add ~/bin to PATH in .bash_profile
  done

#  I got real tired of finding the snapshot in the AUR section of wiki.archlinux.org, downloading
#    it manually to ungzip and untar.  Then cd'ing in and makepkg -si
#    Thus: the acquire-aur.sh script.
#  I was trying to get starman to install at the time, lots more prereq's for that...

# ---------------------------------------------------------------------------------------
# -- More notes to follow once I do this install at least once by cloning the git repo --
# ---------------------------------------------------------------------------------------

