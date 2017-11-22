#! /usr/bin/env python
# -*- coding: utf-8 -*-

""" logon-script für windows-clients in der domäne kmt.
    momentan werden thunderbird- und firefox-profile mit
    bestimmten grundeinstellungen angelegt """

import kmt, argparse, tempfile, os, logging


def setup_args():
    """ parsen von kommandozeilen-argumenten via argparse """

    cli_options = argparse.ArgumentParser(description =\
      "logon-script für nutzer_innen der ad-domäne kmt", epilog =
      "das script benötigt python (o rly?) und das modul kmt, mehr / "
      "ausführlichere dokumentation im wiki und auch im script selbst",
      formatter_class=argparse.ArgumentDefaultsHelpFormatter )

    gen_opts = cli_options.add_argument_group("gen_opts",
      "generische optionen")
    gen_opts.add_argument("--verbose", "-v", default = False,
      action = "count", help = "debugging aktivieren / debug-level "
      "hochschrauben, kann mehrmals angegeben werden")
    gen_opts.add_argument("--path_settings", default = settings_path, help =
      "base-pfad für konfigurationsdateien")
    gen_opts.add_argument("--path_tools", default = tools_path, help = 
      "base-pfad zu diversen vom script benötigten tools")
    gen_opts.add_argument("--domain_name", default = ad_domain,
       help = "name der ad-domäne")

    moz_opts = cli_options.add_argument_group("moz_opts",
      "thunderbird / firefox")
    moz_opts.add_argument("--moz-ff_settings", default = ff_settings, help =
      "ini-datei mit firefox-settings (ohne pfad!)")
    moz_opts.add_argument("--moz-tb_settings", default = tb_settings, help =
      "ini-datei mit thunderbird-settings (ohne pfad!)")
    moz_opts.add_argument("--moz-ff_force_new", default = False,
      action = "store_true",
      help = "erzwingt das anlegen eines neuen firefox-profils")
    moz_opts.add_argument("--moz-tb_force_new", default = False,
      action = "store_true",
      help = "erzwingt das anlegen eines neuen thunderbird-profils")
    moz_opts.add_argument("--moz-phone_def", default = "+49 30/300 903 0",
       help = "default-telefonnummer")
    return(cli_options.parse_args())


### here we go …

# unicode für cmd-shell
kmt.utils.fix_cmd_unicode()
# logging ist schön
log = kmt.utils.setup_logger("{}/{}.log".format(tempfile.gettempdir(), 
  os.path.basename(__file__)))
log.info(u"… start")

#  default-werte für globale variablen klarmachen (vorgabe für cli-paramter)
ff_settings = "firefox-settings.ini"
tb_settings = "thunderbird-settings.ini"
ldap_settings = {"user": "cn=ldapauth,ou=pseudo-nutzer,ou=kmt-users,dc=ad,"
  "dc=kinemathek,dc=de", "pw": "fixme", "cert": "ldap-ca-crt.pem", "base_dn":
  "ou=kmt-users,dc=ad,dc=kinemathek,dc=de"}
ad_domain = "ad.kinemathek.de"
try:
    logonserver = os.environ["LOGONSERVER"]
except KeyError:
    log.critical("… %LOGONSERVER% ist nicht definiert ?!")   
    sys.exit(1)
# logonserver = "//sarandon"
settings_path = os.path.normpath("{}.{}/netlogon/kmt-logon/settings/".\
  format(logonserver, ad_domain))
tools_path = os.path.normpath("{}.{}/netlogon/kmt-logon/tools/".\
  format(logonserver, ad_domain))

# cli-argumente parsen
args = setup_args()
if args.verbose == 1:
    log.setLevel(logging.DEBUG)
elif args.verbose > 1:
    log.setLevel(logging.TRACE)

# okay, business. thunderbird …
log.debug(u"… thunderbird")
tbp = kmt.moz_profiles.tbprofile(args.path_settings, args.path_tools,
  args.moz_tb_settings, args.domain_name, ldap_settings)
if args.moz_tb_force_new:
    tbp.rename_profile()
if not tbp.exists():
    tbp.create()
tbp.query_ldap()
tbp.change_settings("mandatory")
if tbp.is_new:
    tbp.change_settings("optional")
tbp.done()

# firefox …
log.debug(u"… firefox")
ffp = kmt.moz_profiles.ffprofile(args.path_settings, args.path_tools,
  args.moz_ff_settings, args.domain_name, ldap_settings)
if args.moz_ff_force_new:
    ffp.rename_profile()
if not ffp.exists():
    ffp.create()
ffp.query_ldap()
ffp.change_settings("mandatory")
if ffp.is_new:
    ffp.change_settings("optional")
ffp.done()
