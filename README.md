# dw

## INSTALL

This tool depend on osdep from aircrack-ng project. (Note: `git submodule init && git submodule update`)

    make
    sudo make install

## EXAMPLE

    root@exp# airmon-ng wlan0
    root@exp# dw mon0 <bssid> -b <file_with_macs>

## MORE OPTIONS

    man 8 dw

## LICENSE

GPLv2

## AUTHORS

Written by [Nedyalko Dyakov](https://github.com/ndyakov) and [Aleksandar Ivanov](https://github.com/bliof).

with code taken from:
* Using 'osdep' Library from www.aircrack-ng.org project for frame injection
(idea taken from mdk3 by Pedro Larbig)
