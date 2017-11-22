# kmt-logon
… a script for setting up mozilla (ie., thunderbird or firefox) profiles with meaningful presets on windows clients, without user interaction. the script tries to extract relevant settings and values from a ldap directory, does templating to generate a customisable *prefs.js* file with various mandatory and optional settings and deals with certificates.

please run
```
kmt-logon.py --help
```
to get a list of available options. running the script with the `--verbose` flag (which can be repeated) produces a lot of diagnostic output on the terminal and in the logfile *kmt-logon.py.log*. the location of the logfile depends on environment variables, it can usually be found in */tmp* (linux) or *%userprofile%\AppData\Local\Temp* (the other os).

## requirements
kmt-logon is a python script, so it needs a python interpreter … other requirements are:
* [python-ldap](https://pypi.python.org/pypi/python-ldap)
* a compiled version of mozilla's `certutil.exe` (provided)
* tweaking of various domain-/ldap-related settings in *kmt-logon.py* itself (lines 60 ff.)
* certificates in *settings/certs*

## how it works
kmt-logon is controlled by two configuration files - *firefox-settings.ini* and *thunderbird-settings.ini*, both can be found in the *settings*-directory. these ini-style files contain various settings which will be written to *prefs.js*-files for thunderbird and firefox. to personalise these settings, templating will be done: for instance,
```
mail.identity.id1.htmlSigText="${displayname_from_ldap}\r\nyour company\r\nphone: ${tel_from_ldap}\r\n"
```
will replace the `${displayname_from_ldap}` and `${tel_from_ldap}`-variables with appropriate values pulled from your ldap directory.

the settings are arranged in various sections:
### mandatory settings
can be found in [mandatory] and will be set every time the script runs.
### optional settings
are defined in the [optional] sections and will only be set during the initial creation of a profile.
### certificates
you may want to define various certificates as trustworthy or blacklist other certificates … these certificates should be placed in the *settings/certs*-directory, the relevant sections in the ini-files are:
* [certs-whitelist] - certs to be treated as trustworthy
* [certs-blacklist] - certs that will be removed from mozillas cert store
* [certs-override-whitelist] - certs to be treated as trustworthy, even if hostname and cn are different. the format of these entries is `certname.pem={complete line imported from cert_override.txt}`
* [certs-override-blacklist] - certs with hostname!=dn that will be removed from mozillas cert store, format as above
