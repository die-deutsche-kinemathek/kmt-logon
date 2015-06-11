#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys, hashlib, subprocess

cu = subprocess.Popen([os.path.normpath("\\\\sarandon.ad.kinemathek.de/netlogon/kmt-logon/tools/certutil/certutil.exe"), "-L", "-d", sys.argv[1]], stdout=subprocess.PIPE, bufsize=1)
certs = cu.communicate()[0].split("\n")[4:]
for cert in certs:
    name = cert[:50].rstrip()
    if name:
      proc = subprocess.Popen([os.path.normpath("\\\\sarandon.ad.kinemathek.de/netlogon/kmt-logon/tools/certutil/certutil.exe"),
        "-L", "-d", sys.argv[1], "-n", name, "-r"],
        stdout=subprocess.PIPE)
      fp =  hashlib.sha256(proc.communicate()[0]).hexdigest()
      print(u"name: {}, sha256-fingerprint: {}".format(name, fp))

