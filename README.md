# wpakey (1H)                 WIFI hacker's manual                  wpakey (1H)

## NAME

wpakey - monitor mode WPA1/WPA2 online password bruteforcer

## SYNOPSIS

    cat password.lst | wpakey -i wlan0 -b bssid -t timeout -a -f

## DESCRIPTION

reads password candidates from stdin and tries to connect to the specified AP.
the wifi apapter needs to be in **monitor mode** and on the right channel
already.

password candidates with length > 64 and < 8 will be ignored.

note that some access points (most notably *hostapd*) insist on getting ACK
responses on every single unicast packet. due to tight timeout constraints,
it is not possible to generate this ACK in due time in software, so the AP will
not send EAPOL packet M1 after the association response, or if it sends it, will
not accept our M2 packet without an ACK for M1, which makes it impossible to
distinguish whether the password is correct, or the router bitchy.

the only fix for this issue is the so-called "active monitor" mode.
currently, this feature can only be activated on *ath9k* and *mt7601u* drivers
using `iw dev wlan1 set monitor active`. `iw list` or `iw phyX show` can
tell you whether the feature is implemented, it will print
`Device supports active monitor (which will ACK incoming frames)` if supported.
note that even though this feature cannot be actively activated on *ath9k_htc*
devices, some or all of them have this behaviour turned on by default, so
it may well be that other devices behave the same.

therefore, it is highly recommend to use an adapter with one of the mentioned
chipsets for a reliable result.

on the bright side, if we can get the targetted AP to send M1 (regardless of
whether the password we send during M2 is correct), we can retrieve
its PMKID (if it sends one) and crack it with john the ripper instead.

## RETURN VALUE

if the correct password is found, it will be displayed on stdin and the
program will exit with status 0.
if the correct password is not found, exits with status 1.

## ERRORS

No errors are defined.
The following sections are informative.

## RATIONALE

it is possible to test password candidates online using a patched version
of wpa_supplicant (see KEEP/wpa_supplicant-cracker.patch and
KEEP/wpacracker in sabotage-linux repo), however it is very slow, and it
is annoying to switch from monitor mode to managed mode during pentesting.

## FUTURE DIRECTIONS

currently only WPA1/2 in AES CCMP mode is supported. support for TKIP,
WEP and other ciphers may be added in the future.

## COPYRIGHT
(C) 2018 rofl0r

the crypto code in `crypto/`, `wsupp_crypto.c` and the function `pmk_to_ptk()`
were taken from https://github.com/arsv/wsupp-libc which is licensed under the
GPLv3.

due to the viral nature of the GPL, this project is currently licensed under
the GPLv3.

## THANKS
thanks to arsv for well commented, concise code.
thanks to dragorn, Mister_X, Zero_Chaos for giving valuable tips.
