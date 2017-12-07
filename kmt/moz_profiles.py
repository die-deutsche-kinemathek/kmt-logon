#! /usr/bin/env python
# -*- coding: utf-8 -*-

""" verwaltung von thunderbird- und firefox-profilen """

import logging, re, subprocess, datetime, ldap, hashlib, os, sys, \
  ConfigParser, string, codecs
from utils import kmt_configparser


class mozprofile:
    """ klasse, die thunderbird- und firefox-profile abstrahiert """

    def exists(self):
        """ überprüft, ob bereits eine profil-datei existiert und der pfad
            zum profil den konventionen entspricht """

        def fix_profilepath(prof_path, ini_section):
            """ ändert die von firefox/thunderbird zufällig benamsten profile
                entsprechend der konfiguration, damit bestimmte pfade vom
                roaming ausgenommen werden können """
            suffix = os.path.basename(os.path.normpath(prof_path))
            self.log.trace(u"    … profil-suffix: {}".format(suffix))
            if suffix != self.profile_name:
                fixed_suffix = prof_path.rstrip(suffix) + self.profile_name
                old_path = os.path.normpath(os.path.join(path, prof_path))
                new_path = os.path.normpath(os.path.join(path, fixed_suffix))
                self.log.debug(u"    … profilverzeichnis wird von {} in {} "
                  "umbenannt".format(old_path, new_path))
                os.rename(old_path, new_path)
                self.log.debug(u"    … neuer profilpfad wird in profiles.ini"
                  " geschrieben")
                config.set(ini_section, "Path", fixed_suffix)
                config.set(ini_section, "Default", 1)
                config_file = open(os.path.normpath(path + "/profiles.ini"), "w")
                config.write(config_file)
                config_file.close()
            else:
                fixed_suffix = prof_path
            return fixed_suffix

        self.log.info(u"… mozprofile.exists()")
        profile_exists = False
        path = os.path.normpath(u"{}/{}/".format(self.env["appdata"],
          self.profile_path))
        config = kmt_configparser()
        config.optionxform = str
        self.log.debug(u"  … suche nach profiles.ini in {}".format(path))
        if config.read(os.path.normpath(path + "/profiles.ini")):
            self.log.trace(u"    … profiles.ini gefunden")
            # bei mehr als einem profil: default raussuchen
            profiles = config.sections()
            profiles.remove("General")
            if len(profiles) > 1:
                for section in profiles:
                    if config.has_option(section, "Default"):
                        profile = config.get(section, "Path")
                        self.log.debug(u"  … pfad zum default-profil: {}".\
                          format(profile))
                        profile = fix_profilepath(profile, section)
            else: 
                profile = config.get(profiles[0], "Path")
                self.log.debug(u"  … pfad zum einzigen profil: {}".\
                  format(profile))
                profile = fix_profilepath(profile, profiles[0])
            self.env["profile_path"] = os.path.normpath(path + "/" + profile)
            self.env["prefs"] = os.path.normpath(self.env["profile_path"] +
              "/prefs.js")
            # nachschauen, ob im profil-pfad eine prefs.js existiert
            if os.path.isfile(self.env["prefs"]):
                self.log.debug(u"  … prefs.js in {} gefunden".\
                  format(self.env["profile_path"]))
                profile_exists = True
            else:
                self.log.debug(u"  … keine gültige prefs.js in {} gefunden".\
                  format(self.env["profile_path"]))
        else:
            self.log.info(u"  … profiles.ini nicht gefunden")
        return(profile_exists)
    

    def create(self, been_here = False):
        """ lässt tb / ff ein neues profil anlegen """
        self.log.info(u"… mozprofile.create()")
        self.log.info(u"  … führe {} aus, um ein neues profil zu erstellen".\
          format(self.exe_path))
        subprocess.call([self.exe_path, "-CreateProfile", 
          self.env["username"]])
        if not self.exists():
            if not been_here:
                self.log.debug(u"  … uh-oh - das neu angelegte profil ist "
                  "nicht das default-profil. als letzte rettung wird "
                  "profiles.ini umbenannt und ein weiteres neues profil "
                  "angelegt.")
                self.backup(os.path.normpath(u"{}/{}/{}".\
                  format(self.env["appdata"], self.profile_path,
                  "/profiles.ini")))
                self.create(been_here = True)
            else:
                self.log.error(u"  … das anlegen eines neuen profils ging " 
                  "schief! ")
                sys.exit(1)
        self.is_new = True


    def query_ldap(self):
        """ liest relevante persönliche daten aus dem ad-ldap """
        self.log.info(u"… mozprofile.query_ldap()")
        ls = "ldap://{}.{}".format(self.env["logonserver_name"],
          self.domain_name)
        self.log.debug(u"  … hole relevante daten aus dem ldap: {}".format(ls))
        # ca-cert setzen geht nur global ?!
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, os.path.normpath(
          self.settings_path + "/certs/" + self.ldap_settings["cert"]))
        try:
            lc = ldap.initialize(ls)
        except Exception as e:
            self.log.error(u"  … kann keine verbindung zu {} aufbauen: {}".\
              format(ls, e))
            sys.exit(1)
        lc.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        lc.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        lc.set_option(ldap.OPT_REFERRALS, 0)
        try:
            lc.start_tls_s()
        except Exception as e:
            self.log.error(u"  … kann verbindung zu {} nicht per tls "
              "absichern: {}".format(ls, e))
            sys.exit(1)
        try:
            lc.bind_s(self.ldap_settings["user"], self.ldap_settings["pw"])
        except Exception as e:
            self.log.error(u"  … konnte {} nicht gegen {} authentifizieren!".\
              format(self.ldap_settings["user"], ls))
            sys.exit(1)
        self.log.trace(u"    … suche nach: {}".format(self.env["username"]))
        result = lc.search_s(self.ldap_settings["base_dn"],
          ldap.SCOPE_SUBTREE, "uid={}".format(self.env["username"]), 
          ["cn", "telephoneNumber", "displayname", "mail",
          "distinguishedname"])
        self.log.trace(u"    … ergebnis: {}".format(result))
        if len(result) != 1:
            self.log.error(u"    … zu viele oder zu wenige treffer im neuen ldap!")
            sys.exit(1)
        else:
            # dn, attrs = result[0].decode("utf-8")
            dn = result[0][0].decode("utf-8")
            attrs = result[0][1]
            self.log.debug(u"    … ergebnis: dn: {}, attrs: {}".format(dn, attrs))
            self.env["cn_from_ldap"] = attrs["cn"][0]
            self.env["dn_from_ldap"] = attrs["distinguishedName"][0]
            try:
                self.env["tel_from_ldap"] = attrs["telephoneNumber"][0]
            except KeyError:
                self.env["tel_from_ldap"] = self.moz-phone_def
            self.env["mail_from_ldap"] = attrs["mail"][0]
            self.env["displayname_from_ldap"] = attrs["displayName"][0]
        lc.unbind_s()
        # quirk: leere werte zulassen
        self.env["empty"] = ""
        self.log.trace(u"    … gesetzte werte: {}".format(self.env))


    def change_settings(self, mode):
        """ liest daten aus einem vorhandenen profil und ersetzt diese, falls
            nötig. hier werden außerdem zertifikate verarztet """

        def settings_from_file(what):
            """ liest einstellungen aus ini_file """
            self.ini = ConfigParser.RawConfigParser(allow_no_value = True)
            # mozilla ist case sensitive …
            self.ini.optionxform = str
            self.items = ""
            self.log.debug(u"    … lese einstellungen aus {} , abschnitt {}".\
              format(self.ini_file, what))
            if self.ini.read(self.ini_file):
                if self.ini.has_section(what):
                    if what == "mandatory":
                        force_settings = True
                    else:
                        force_settings = False
                    for self.item in self.ini.items(what):
                        set_value(*self.item, force = force_settings)
                else:
                    self.log.info("      … der abschnitt {} fehlt!".\
                      format(what))
            else:
                self.log.error(u"    … datei {} ist nicht lesbar!".\
                  format(self.ini_file))
                sys.exit(1)

        def get_value(key):
            """ liefert den wert für key aus dem profil zurück """
            try:
                value = self.content[key]
            except KeyError:
                value = None
            return(value)

        def set_value(key, value, force=False):
            """ schreibt einen key/value-eintrag in das profil, wenn dieser
                noch nicht vorhanden ist oder das schreiben mit force erzwungen
                wird. templating: ${foo} in keys oder values wird durch die
                variable foo ersetzt"""

            new_value = string.Template(value).substitute(self.env)
            if value != new_value:
                self.log.trace(u"      … value {} wurde durch {} ersetzt".\
                  format(value.decode("utf-8"), new_value.decode("utf-8")))
            old_value = get_value(key)
            if old_value:
                self.log.trace(u"      … key {} existiert schon, wert: {}".\
                  format(key, old_value.decode("utf-8")))
                if force and (old_value.strip() != new_value.strip()):
                    self.log.debug(u"      … key {} wird aktualisiert".format(key))
                    clear_value(key)
                    self.content[key] = new_value
                    self.is_dirty = True
                else:
                    self.log.trace(u"      … wird nicht aktualisiert")

            else:
                self.log.debug(u"      … key {}, value {} hinzugefügt".\
                  format(key, value.decode("utf-8")))
                self.content[key] = new_value
                self.is_dirty = True

        def clear_value(key):
            """ löscht den wert key aus dem profil """
            self.content.pop(key, None)

        def do_certs():
            """ zertifikats-handling """
            cu = os.path.normpath(self.tools_path + "/certutil/certutil.exe")
            certstuff = ConfigParser.RawConfigParser(allow_no_value = True)
            self.log.debug(u"    … suche nach cert-settings in {}".\
              format(self.ini_file))
            try:
                certstuff.read(self.ini_file)
                self.log.trace(u"      … gefunden")
                wl = certstuff.items("certs-whitelist")
                wl_ca = certstuff.items("certs-ca-whitelist")
                bl = certstuff.items("certs-blacklist")
                override_wl = certstuff.items("certs-override-whitelist")
                override_bl = certstuff.items("certs-override-blacklist")
            except ConfigParser.NoSectionError as e:
                self.log.info(u"    … ein abschnitt fehlt: {}".format(e))
            self.log.debug(u"      … erstelle liste der importierten certs und "
              "ihrer fingerprints")
            certs_by_fp = {}
            certs = []
            proc = subprocess.Popen([cu, "-L", "-d", self.env["profile_path"]],
              stdout=subprocess.PIPE, bufsize=1)
            certs = proc.communicate()[0].split("\n")[4:]
            for cert in certs:
                name = cert[:50].rstrip()
                if name:
                    proc = subprocess.Popen([cu, "-L", "-d", 
                      self.env["profile_path"], "-n", name, "-r"],
                      stdout=subprocess.PIPE)
                    fp =  hashlib.sha256(proc.communicate()[0]).hexdigest()
                    self.log.trace(u"        … name: {}, sha256-fingerprint: "
                      "{}".format(name, fp))
                    certs_by_fp[fp] = name
            certs_names = certs_by_fp.values()
            self.log.debug(u"    … hinzufügen von certs auf der whitelist")
            for cert in wl:
                if cert[0] not in certs_names:
                    cert_path = os.path.normpath("{}/certs/{}".\
                      format(self.settings_path, cert[0]))
                    self.log.trace(u"      … {}".format(cert_path))
                    subprocess.call([cu, "-A", "-d",self.env["profile_path"],
                      "-i", cert_path, "-n", cert[0], "-t", "P,,"])
            self.log.debug(u"    … hinzufügen von ca-certs auf der whitelist")
            for cert in wl_ca:
                if cert[0] not in certs_names:
                    cert_path = os.path.normpath("{}/certs/{}".\
                      format(self.settings_path, cert[0]))
                    self.log.trace(u"      … {}".format(cert_path))
                    subprocess.call([cu, "-A", "-d",self.env["profile_path"],
                      "-i", cert_path, "-n", cert[0], "-t", "C,,"])
            self.log.debug(u"    … löschen von certs auf der blacklist")
            # zum löschen müssen certs über ihren sha256-fingerprint 
            # referenziert werden, alles andere ist nicht verläßlich genug
            for name, fp in bl:
                if fp in certs_by_fp:
                    self.log.debug(u"      … lösche {}, sha256-fingerprint: "
                      "{}".format(certs_by_fp[fp], fp))
                    subprocess.call([cu, "-D", "-d", self.env["profile_path"],
                      "-n", certs_by_fp[fp]])
            self.log.debug(u"    … overrides für certs, bei denen cn und "
              u"hostname nicht übereinstimmen")
            override_file = os.path.normpath(self.env["profile_path"] +
              "/cert_override.txt")
            try:
                overrides = open(override_file, "r").readlines()
            except IOError:
                self.log.info(u"    … {} ist nicht lesbar".\
                  format(override_file))
                overrides = []
            for cert, override in override_wl:
                override = "\t".join(override.split()) + "\n"
                if override not in overrides:
                    self.log.trace(u"      … {} wird hinzugefügt".\
                      format(override))
                    overrides.append(override)
            for cert, override in override_bl:
                override = "\t".join(override.split()) + "\n"
                if override in overrides:
                    self.log.trace(u"      … {} wird gelöscht".\
                      format(override))
                    overrides.remove(override)
            try:
                of = open(override_file, "w")
                for override in overrides:
                    of.write(override)
            except IOError:
                self.log.error(u"    … {} ist nicht schreibbar".\
                  format(override_file))
                sys.exit(1)

        def load_profile():
            """ liest vorhandene profildaten """
            prefs_re = re.compile(r"^user_pref\(\"(.*?)\",\s*?(.*)\);$")
            self.log.debug(u"  … lese {}".format(self.env["prefs"]))
            try:
                fh = open(self.env["prefs"], "r")
                stuff = fh.readlines()
                fh.close()
            except IOError:
                self.log.error(u"    … profildatei {} ist nicht lesbar!".\
                  format(self.env["prefs"]))
                sys.exit(1)
            for line in stuff:
                self.log.trace(u"    … inhalt: {}".format(line.decode("utf-8").\
                  strip("\n\r")))
                pref = re.search(prefs_re, line)
                if pref:
                    key = pref.group(1)
                    value = pref.group(2).strip("\n\r")
                    self.log.trace(u"    … ist relevant, key: {}, value: {}".\
                      format(key.decode("utf-8"), value.decode("utf-8")))
                    self.content[key] = value
            self.log.trace(u"    … done. geparste werte: {}".format(self.content))
            self.loaded = True

        def do_hacks(mode):
            """ wundertüte für hässliche hacks / warum auch immer nötige
                anpassungen, die sich nicht per templating erledigen lassen.
                bitte sparsam verwenden. """
            self.log.info(u"  … hässliche häcks")
            # hack für mail.accountmanager.accounts="account1,account2" im
            # thunderbird-profil - das darf nur beim neuanlegen eines profils
            # gesetzt werden
            if self.__class__.__name__ == "tbprofile" and self.is_new and \
              mode == "mandatory":
                self.log.debug(u"    … mail.accountmanager.accounts")
                self.content["mail.accountmanager.accounts"] = \
                  "\"account1,account2\""

        self.log.info(u"… mozprofile.change_settings({})".format(mode))
        if not self.loaded:
            load_profile()
        if mode == "mandatory":
            self.log.info(u"  … obligatorische einstellungen")
            settings_from_file("mandatory")
            self.log.info(u"  … zertifikate werden verarztet")
            do_certs()
        if mode == "optional":
            self.log.info(u"  … optionale einstellungen")
            settings_from_file("optional")
        do_hacks(mode)


    def save_profile(self):
        """ speichert die profildaten """
        self.log.debug(u"  … schreibe profildatei {}".format(self.env["prefs"]))
        try:
            fh = codecs.open(self.env["prefs"], "w", "utf-8")
            for key in sorted(self.content.iterkeys()):
                try:
                    value = str(self.content[key]).strip()
                except UnicodeEncodeError:
                    value = str(self.content[key].decode("utf-8")).strip()
                # fh.write("""user_pref("%s", %s);\n""" % (key, 
                #  value.decode("utf-8")))
                fh.write(u"""user_pref("{}", {});\n""".\
                  format(key.decode("utf-8"), value.decode("utf-8")))
            fh.close()
        except IOError:
            self.log.error(u"  … profildatei {} ist nicht schreibbar!".\
              format(self.vars["prefs"]))

            
    def rename_profile(self):
        """ benennt ein existierendes profil um """
        self.log.info(u" … altes profil wird umbenannt")
        self.backup(os.path.normpath(u"{}/{}/".format(self.env["appdata"],
          self.profile_path)))


    def backup(self, name):
        """ benennt das als argument übergebene objekt im filesystem um """
        name_new = name + datetime.datetime.now().strftime(" - %Y%m%d-%H%M%S")
        try:
            self.log.debug(u"  … umbennen von {} nach {}".format(name, name_new))
            os.rename(name, name_new)
        except (IOError,WindowsError):
            self.log.error(u"  … umbennen von {} nach {} ging schief".\
              format(name, name_new))
            sys.exit(1)


    def done(self):
        """ änderungen schreiben, falls nötig """
        if self.is_dirty:
            self.log.info(u"… es gab änderungen, diese werden geschrieben")
            self.save_profile()
        else:
            self.log.info(u"… keine zu schreibenden änderungen in der prefs.js")



    def __init__(self, settings_path, tools_path, ini_file):
        """ init für mozprofile """
        self.is_new = False      # neu angelegtes profil?
        self.loaded = False      # wurde ein existierendes profil schon geladen?
        self.is_dirty = False    # gibt es änderungen im profil?
        self.content = {}        # profildaten       
        self.env = {}            # variablen aus dem environment
        self.settings_path = settings_path.rstrip("\\/")
        self.tools_path = tools_path.rstrip("\\/")
        self.ini_file = ini_file

        # werte aus dem environment holen - welche_r nutzer_in wird bearbeitet,
        # welche server werden gefragt usw.
        self.log.debug(u"  … hole relevante daten aus dem environment")
        env_vars = ["appdata", "username", "logonserver", "programfiles(x86)",
          "programw6432"]
        for key in env_vars:
            self.log.trace(u"    … variable: {}".format(key))
            try:
                value = os.environ[key]
            except KeyError:
                self.log.error(u"  … variable {} existiert nicht!".format(key))
                sys.exit(1)
            self.log.trace(u"      … wert: {}".format(value))
            self.env[key] = value
        self.env["logonserver_name"] = self.env["logonserver"].lstrip("\\")


class tbprofile(mozprofile):
    """ profil für thunderbird """
    def __init__(self, settings_path, tools_path, ini_file, domain_name,
        ldap_settings, profile_name):
        # __init__ der eltern-klasse
        self.log = logging.getLogger("kmt-logon.tb")
        self.log.info(u"… tbprofile.__init__")
        mozprofile.__init__(self, settings_path, tools_path, ini_file) 
        self.profile_path = os.path.normpath("Thunderbird/")
        self.exe_path = os.path.normpath("{}/Mozilla Thunderbird/"
          "thunderbird.exe".format(self.env["programfiles(x86)"]))
        self.ini_file = os.path.normpath(settings_path + "/" + ini_file)
        for var in ["domain_name", "ldap_settings", "profile_name"]:
            setattr(self, var, eval(var))


class ffprofile(mozprofile):
    """ profil für firefox """
    def __init__(self, settings_path, tools_path, ini_file, domain_name,
        ldap_settings, profile_name):
        self.log = logging.getLogger("kmt-logon.ff")
        self.log.info(u"… ffprofile.__init__")
        mozprofile.__init__(self, settings_path, tools_path, ini_file)
        self.profile_path = os.path.normpath("Mozilla/Firefox/")
        self.exe_path = os.path.normpath("{}/Mozilla Firefox/"
          "firefox.exe".format(self.env["programw6432"]))
        self.ini_file = os.path.normpath(settings_path + "/" + ini_file)
        for var in ["domain_name", "ldap_settings", "profile_name"]:
            setattr(self, var, eval(var))

