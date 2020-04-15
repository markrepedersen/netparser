# rust_wifi_deauther
A deauther ("jammer") implemented in Rust.

Using the fact that most access points are insecure in general, the ability to mimic 
client devices to transmit [Authentication Frames](https://mrncciew.com/2014/10/10/802-11-mgmt-authentication-frame/)
on behalf of other devices can act as a 'jammer' in local areas. 

This will set up an available interface to monitor for devices connected to a subnet and send (1*) authentication frame to
the listening Access Point on behalf of each device and (1*) to each device on behalf of the Access Point.

The following can be done if your network card does not support Monitoring mode:

# On MacOS: 

This will make a symlink to `/usr/local/bin/airport`, allowing you to run a less verbose `airport` command, since MacOS for some reason has this command in a not-so-easy-to-find place.
- `sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport`

This will enable Monitoring mode on network interace `en0` (wlan1 for linux) on channel 1.
- `sudo airport en0 sniff 1`
