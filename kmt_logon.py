#! /usr/bin/env python
# -*- coding: utf-8 -*-

""" logon-script für windows-clients in der domäne kmt """

import argparse, re, ConfigParser, os, sys, tempfile, logging, Tkinter, \
  subprocess, datetime, string, kmt, ldap, hashlib, shutil, sqlite3, base64


def setup_args():
    """ parsen von kommandozeilen-argumenten via argparse """

    cli_options = argparse.ArgumentParser(description =\
      "logon-script für nutzer_innen der ad-domäne kmt", epilog =
      "… das script benötigt python (o rly?) und das module kmt, mehr / " +
      "ausführlichere dokumentation im wiki und auch im script selbst",
      formatter_class=argparse.ArgumentDefaultsHelpFormatter )

    gen_opts = cli_options.add_argument_group("gen_opts",
      "generische optionen")
    gen_opts.add_argument("--verbose", "-v", default = False,
      action = "count", help = "debugging aktivieren / debug-level " +
      "hochschrauben, kann mehrmals angegeben werden")
    gen_opts.add_argument("--password", default = False, action = "store_true",
      help = "anzeige des password-prompts erzwingen")
    gen_opts.add_argument("--path_settings", default = settings_path, help =
      "base-pfad für konfigurationsdateien")
    gen_opts.add_argument("--path_tools", default = tools_path, help = 
      "base-pfad zu diversen vom script benötigten tools")

    moz_opts = cli_options.add_argument_group("moz_opts",
      "thunderbird / firefox")
    moz_opts.add_argument("--moz-ff_settings", default = ff_settings, help =
      "ini-datei mit firefox-settings (ohne pfad!)")
    moz_opts.add_argument("--moz-tb_settings", default = tb_settings, help =
      "ini-datei mit thunderbird-settings (ohne pfad!)")
    moz_opts.add_argument("--moz-ff_force", default = False,
      action = "store_true",
      help = "erzwingt das anlegen eines neuen firefox-default-profils")
    moz_opts.add_argument("--moz-ff_update", default= False,
      action = "store_true",
      help = "erzwingt das überschreiben vorhandener kritischer " +
        "einstellungen im firefox-profil")
    moz_opts.add_argument("--moz-tb_force", default = False,
      action = "store_true",
      help = "erzwingt das anlegen eines neuen thunderbird-default-profils")
    moz_opts.add_argument("--moz-tb_update", default= False,
      action = "store_true",
      help = "erzwingt das überschreiben vorhandener kritischer " +
        "einstellungen im tunderbird-profil")
    return(cli_options.parse_args())


def get_password():
    """ benutzer_in das passwort eintippen lassen """

    def entry_done(foo=None):
        global pw
        pw = (entry.get())
        fenster.destroy()

    fenster = Tkinter.Tk()
    fenster.bind("<Return>", entry_done)
    Tkinter.Label(fenster, text="für die einrichtung des kmt-accounts " +\
      "bitte das kmt-passwort eintippen:", padx = 10, pady = 10).pack()
    entry = Tkinter.Entry(fenster, show="*")
    entry.pack(pady = 3)
    entry.focus_set()
    button = Tkinter.Button(fenster, text="okay", command=entry_done, padx = 3,
      pady = 3)
    button.pack(pady = 10)
    fenster.mainloop()
    log.debug(u"  … passwort done.")


class mozprofile:
    """ klasse, die thunderbird- und firefox-profile abstrahiert """

    is_new = False      # neu angelegtes profil ?
    is_dirty = False    # änderungen im profil?
    content = {}        # profildaten       
    vars = {}           # variablen für das temnplating, die werte kommen aus
                        # dem environment oder aus den ldap-verzeichnissen
    
    def __init__(self):
        self.pp = ""        # pfad zum profil
        self.fn = ""        # pfad zu pref.js im profil
        self.path_settings = self.path_settings.rstrip("\\/")
        self.path_tools = self.path_tools.rstrip("\\/")

    def check_profile(self):
        """ überprüft, ob bereits eine profil-datei existiert """
        profile_exists = False
        path = os.environ["APPDATA"] + "\\" + self.profile_path
        config = ConfigParser.RawConfigParser()
        log.debug(u"  … suche nach profiles.ini in %s" % path)
        if config.read(path + "\\profiles.ini"):
            log.trace(u"    … profiles.ini gefunden")
            # bei mehr als einem profil: default raussuchen
            profiles = config.sections()
            profiles.remove("General")
            if len(profiles) > 1:
                for section in profiles:
                    if config.has_option(section, "Default"):
                        found = config.get(section, "Path")
                        log.debug(u"  … pfad zum default-profil: %s" % found)
            else: 
                found = config.get(profiles[0], "Path")
                log.debug(u"  … pfad zum einzigen profil: %s" % found)
            self.pp = path + found.replace("/", "\\")
            # nachschauen, ob im profil-pfad eine prefs.js existiert
            if os.path.isfile(self.pp + "\\prefs.js"):
                log.debug(u"  … prefs.js in %s gefunden" % found)
                profile_exists = True
                self.fn = self.pp + "\\prefs.js"
            else:
                log.debug(u"  … keine prefs.js in %s gefunden" % found)
        else:
            log.info(u"  … profiles.ini nicht gefunden")
        return(profile_exists)
    
    def create_profile(self, been_here = False):
        """ lässt tb / ff ein neues profil anlegen """
        app_path = os.environ["ProgramFiles(x86)"] + "\\" + self.exe_path
        username = os.environ["USERNAME"]
        log.info(u"  … führe %s aus, um ein neues profil zu erstellen" %
          app_path)
        subprocess.call([app_path, "-CreateProfile", username])
        if not self.check_profile():
            if not been_here:
                log.debug(u"  … uh-oh - das neu angelegte profil ist nicht " +
                  "das default-profil. als letzte rettung wird profiles.ini " +
                  "umbenannt und ein weiteres neues profil angelegt.")
                self.backup(os.environ["APPDATA"] + "\\" + self.profile_path +
                  "\\profiles.ini")
                self.create_profile(been_here = True)
            else:
                log.error(u"  … das anlegen eines neuen profils ging schief! ")
                sys.exit(1)
        else:
            self.is_new = True

    def load_profile(self):
        """ liest profildaten aus der spezifizierten datei und setzt
            variablen für die spätere substitution """
        # werte aus dem environment
        log.debug(u"  … hole relevante daten aus dem environment")
        env_vars = ["appdata", "username", "logonserver"]
        for key in env_vars:
            log.trace(u"    … key: %s" % key)
            try:
                value = os.environ[key]
            except KeyError:
                log.error(u"  … umgebungsvariable %s existiert nicht!" % key)
                sys.exit(1)
            if key == "appdata":
                key = "profile_path"
                value = self.pp
            log.trace(u"       … value: %s" % value)
            self.vars[key] = value
        # werte aus dem alten ldap
        log.debug(u"  … hole relevante daten aus dem alten ldap")
        try:
            lc = ldap.initialize("ldap://ldapmaster.kinemathek.de")
        except Exception, e:
            log.error(u"  … keine verbindung zu ldapmaster.kinemathek.de!")
            sys.exit(1)
        lc.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        search_string = "uid=%s" % self.vars["username"]
        log.trace(u"    … suche nach: %s" % search_string)
        result = lc.search_s("ou=Users,dc=kinemathek,dc=de", 
          ldap.SCOPE_SUBTREE, search_string, ["cn", "mail", "uid", "dn"])
        log.trace(u"    … ergebnis: %s" % result)
        if len(result) != 1:
            log.error(u"    … zu viele oder zu wenige treffer im alten ldap!")
            sys.exit(1)
        else:
            dn, attrs = result[0]
            log.debug(u"    … ergebnis: dn: %s, attrs: %s" % (dn, attrs))
            self.vars["dn_from_old_ldap"] = dn
            self.vars["email_localpart_from_ldap"] = attrs["mail"][0].\
              split("@")[0]
            self.vars["uid_from_old_ldap"] = attrs["uid"][0]
        lc.unbind_s()
        # werte aus dem neuen ldap
        ls = "ldap://%s.ad.kinemathek.de" % self.vars["logonserver"].\
          lstrip("\\")
        log.debug(u"  … hole relevante daten aus dem neuen ldap: %s" % ls)
        # ca-cert setzen geht nur global ?!
        ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
          "%s.ad.kinemathek.de\\" % self.vars["logonserver"] +
          "netlogon\\settings\\certs\\kmt-ldap-ca-crt.pem")
        try:
            # lc = ldap.initialize(ls, trace_level=10)
            lc = ldap.initialize(ls)
        except Exception as e:
            log.error(u"  … kann keine verbindung zu %s aufbauen: %s" %
              (ls, e))
            sys.exit(1)
        lc.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        lc.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
        lc.set_option(ldap.OPT_REFERRALS, 0)
        try:
            lc.start_tls_s()
        except Exception as e:
            log.error(u"  … kann keine verbindung per starttls zu %s " % ls +
              "aufbauen: %s" % e)
            sys.exit(1)
        try:
            user = self.vars["username"] + "@ad.kinemathek.de"
            lc.bind_s(user, pw)
        except Exception as e:
            log.error(u"  … konnte %s nicht gegen %s " % (user, ls) +
              "authentifizieren!")
            sys.exit(1)
        log.trace(u"    … suche nach: %s" % search_string)
        result = lc.search_s("ou=kmt-users,dc=ad,dc=kinemathek,dc=de",
          ldap.SCOPE_SUBTREE, search_string, ["cn", "telephoneNumber"])
        log.trace(u"    … ergebnis: %s" % str(result).encode("utf-8"))
        if len(result) != 1:
            log.error(u"    … zu viele oder zu wenige treffer im neuen ldap!")
            sys.exit(1)
        else:
            dn, attrs = result[0]
            log.debug(u"    … ergebnis: dn: %s" % dn.decode("utf-8") +\
              "attrs: %s" % str(attrs).decode("utf-8"))
            self.vars["cn_from_ldap"] = attrs["cn"][0]
            self.vars["tel_from_ldap"] = attrs["telephoneNumber"][0]
        lc.unbind_s()
        # quirk: leere werte zulassen
        self.vars["empty"] = ""
        log.trace(u"  … gesetzte werte: %s" % self.vars)
        # existierendes profil laden
        prefs_re = re.compile(r"^user_pref\(\"(.*?)\",\s*?(.*)\);$")
        log.debug(u"  … lese  %s" % self.fn)
        try:
            fh = open(self.fn, "r")
            stuff = fh.readlines()
            fh.close()
        except IOError:
            log.error(u"    … profildatei %s ist nicht lesbar!" % self.fn)
            sys.exit(1)
        for line in stuff:
            log.trace(u"    … inhalt: %s" % line.decode("utf-8").strip("\n\r"))
            pref = re.search(prefs_re, line)
            if pref:
                key = pref.group(1)
                value = pref.group(2).strip("\n\r ")
                log.trace(u"    … ist relevant, key: %s, value: %s" %
                  (key.decode("utf-8"), value.decode("utf-8")))
                self.content[key] = value
        log.trace(u"    … done. geparste werte: %s" % self.content)

    def save_profile(self):
        """ speichert die profildaten """
        log.debug(u"  … schreibe profildatei %s" % self.fn)
        try:
            fh = open(self.fn, "w")
            for key in sorted(self.content.iterkeys()):
                value = str(self.content[key])
                # log.trace(u"    … key: %s, value: %s" % (key.decode("utf-8"),
                #  value.decode("utf-8")))
                fh.write("""user_pref("%s", %s);\n""" % 
                  (key, value))
                  # (key.encode("utf-8"), value.encode("utf-8")))
            fh.close()
        except IOError:
            log.error(u"  … profildatei %s ist nicht schreibbar!" % self.fn)
            
    def get_value(self, key):
        """ liefert den wert für key aus dem profil zurück """
        try:
            value = self.content[key]
        except KeyError:
            value = None
        return(value)

    def set_value(self, key, value, force=False):
        """ schreibt einen key/value-eintrag in das profil, wenn dieser noch
            nicht vorhanden ist oder das schreiben mit force erzwungen wird.
            templating: ${foo} in keys oder values wird durch die umgebungs-
            variable foo ersetzt"""

        def set_value_tmpl(key, value):
            """ führt das templating in $value durch und fügt die werte dem
                profil hinzu """
            sub_res = string.Template(value).substitute(self.vars)
            if value != sub_res:
                log.trace(u"      … %s wurde durch %s ersetzt" % \
                  (value.decode("utf-8"), sub_res.decode("utf-8")))
            self.content[key] = sub_res
                    
        self.is_dirty = True
        old_value = self.get_value(key)
        if old_value:
            log.debug(u"      … key %s existiert schon, wert: %s " %
              (key.decode("utf-8"), old_value.decode("utf-8")))
            if force:
                log.trace(u"      … wird aktualisiert")
                self.clear_value(key)
                set_value_tmpl(key, value)
        else:
            log.trace(u"      … key %s, value %s hinzugefügt" % 
              (key.decode("utf-8"), value.decode("utf-8")))
            set_value_tmpl(key, value)

    def clear_value(self, key):
        """ löscht den wert key aus dem profil """
        self.content.pop(key, None)

    def update_profile(self, mode):
        """ schreibt die obligatorischen bzw. optionalen settings in das
            profil, falls nötig
            hier werden außerdem zertifikate verarztet """
        if mode == "mandatory" and (self.is_new or self.force_update):
            log.info(u"  … obligatorische einstellungen werden in das " +\
              "profil geschrieben")
            self.settings_from_file("mandatory")
            log.debug(u"  … zertifikate")
            cu_path = args.path_tools + "\\certutil\\certutil.exe"
            if not os.path.isfile(self.pp + "\\cert8.db"):
                log.debug(u"    … lege neue zertifikats-db an")
                subprocess.call([cu_path, "-N", "-d", self.pp,
                  "--empty-password"])
            else:
                log.debug(u"    … zertifikats-db existierte bereits")
            of = self.pp + "\\cert_override.txt"
            if os.path.isfile(of):
                log.debug(u"    … %s existiert bereits, wird gelesen" % of)
                try:
                    cor = open(of, "r")
                except IOError:
                    log.error(u"    %s kann nicht gelesen werden" % of)
                old_overrides = cor.readlines()
                cor.close()
            else:
                log.debug(u"    … overrides werden neu angelegt")
                old_overrides = []
            new_overrides = {}
            for override in old_overrides:
                fp = override.split()[2].lower()
                new_overrides[fp] = override
            log.debug(u"    … whitelist bearbeiten")
            try:
                wl = open(self.certs_wl, "r")
            except IOError:
                log.error(u"    … %s kann nicht gelesen werden!" %
                  self.certs_wl)
                sys.exit(1)
            good_certs = wl.readlines()
            wl.close()
            for cert in good_certs:
                if not cert.startswith("#"):
                    log.debug(u"      … importiere %s" % cert)
                    name = cert.split()[0]
                    cert_path = args.path_settings + "\\certs\\" + name
                    log.trace(u"        … führe %s aus, um %s zu importieren"
                      % (cu_path, cert_path))
                    subprocess.call([cu_path, "-A", "-d", self.pp, "-i", \
                      cert_path, "-n", name, "-t", "P,,"])
                    if len(cert.split()) > 1:
                        cert_stuff = cert.split()
                        log.debug(u"        … erstelle ausnahmeregelung, " +
                          u"zertifikat %s ist gültig für server %s" %
                          (cert_stuff[0], cert_stuff[1]))
                        if cert_stuff[3].lower() in new_overrides:
                            log.trace(u"        … existierte bereits")
                        else:
                            log.trace(u"        … ist neu, wird hinzugefügt")
                            new_overrides[cert_stuff[3].lower()] = \
                              "\t".join(cert_stuff[1:])
            log.debug(u"    … blacklist bearbeiten")
            try:
                bl = open(self.certs_bl, "r")
            except IOError:
                log.error(u"    … %s kann nicht gelesen werden!" % self.certs_bl)
                sys.exit(1)
            bad_certs = bl.readlines()
            bl.close()
            log.debug(u"      … erstelle liste der importierten certs")
            imp_certs = {}
            proc = subprocess.Popen([args.path_tools +
              "\\certutil\\certutil.exe", "-L", "-d", self.pp], 
              stdout=subprocess.PIPE, bufsize=1)
            certs = proc.communicate()[0].split("\n")[4:]
            for cert in certs:
                name = cert[:50].rstrip()
                if name:
                    proc = subprocess.Popen([args.path_tools + 
                      "\\certutil\\certutil.exe", "-L", "-d", self.pp, "-n",
                      name, "-r"], stdout=subprocess.PIPE)
                    fp =  hashlib.sha256(proc.communicate()[0]).hexdigest()
                    log.trace(u"        … name: %s , sha256-fingerprint: %s"
                      % (name, fp))
                    imp_certs[fp] = name
            for cert in bad_certs:
                if not cert.startswith("#"):
                    fp = cert.lower().rstrip("\n")
                    try:
                        name = imp_certs[fp.replace(":", "")]
                        log.trace(u"     … lösche %s aus der cert-db" % name)
                        subprocess.call([cu_path, "-D", "-d", self.pp, "-n",
                          name])
                    except KeyError:
                        log.trace(u"        … %s war nicht in der cert-db"
                          % fp)
                    if fp in new_overrides:
                        log.trace(u"        … entferne ausnahmeregelung für" +
                          u" %s " % name)
                        del(new_overrides[fp])
            log.trace(u"        … neue ausnahmeregelungen: %s" % 
              str(new_overrides))
            log.debug(u"        … schreibe neue ausnahmeregelungen")
            try:
                cor = open(of, "w")
            except IOError:
                log.error(u"    %s kann nicht gelesen werden" % of)
                sys.exit(1)
            for key, value in new_overrides.iteritems():
                cor.write(value)
            cor.close()
            if self.__class__.__name__ == "tbprofile":
                log.debug(u"  … passwörter für thunderbird")
                pwf = self.pp + "\\signons.sqlite"
                log.trace(u"    … kopiere template-datei")
                try:
                    shutil.copyfile(args.path_settings + \
                    "\\signons-template.sqlite", pwf)
                except IOError:
                    log.error(u"    … template-datei für passwörter konnte " +
                      "nicht nach %s kopiert werden!" % pwf)
                    sys.exit(1)
                log.trace(u"    … schreibe username & passwort")
                sqlc = sqlite3.connect(pwf)
                sql = sqlc.cursor()
                sqlvalues = [("imap://imap.deutsche-kinemathek.de", \
                  "imap://imap.deutsche-kinemathek.de", "", "", "~" + \
                  base64.b64encode(self.vars["email_localpart_from_ldap"] + \
                  "@deutsche-kinemathek.de"), "~" + base64.b64encode(pw), \
                  "0", "{01caffee-babe-babe-babe-b13453b13453}"),
                  ("ldap://ldapmaster.kinemathek.de",
                  "ldap://ldapmaster.kinemathek.de/ou=Users,dc=kinemathek," +\
                  "dc=de??sub?(objectclass=InetOrgPerson)", "", "", "~" + \
                  base64.b64encode(self.vars["dn_from_old_ldap"]), "~" + \
                  base64.b64encode(pw), "0", \
                  "{02caffee-babe-babe-ffff-b13453b13453}")]
                sql.executemany('insert into moz_logins (hostname, httpRealm, \
                  usernameField, passwordField, encryptedUsername, \
                  encryptedPassword, encType, guid) values \
                  (?, ?, ?, ?, ?, ? , ?, ?);', sqlvalues)
                sqlc.commit()
                sqlc.close()
        if mode  == "optional" and self.is_new:
            log.info(u"  … optionale einstellungen werden in das  profil " +\
              "geschrieben")
            self.settings_from_file("optional")

    def rename_profile(self):
        """ benennt das komplette profil um """
        log.info(u" … altes profil wird umbenannt")
        self.backup(self.pp)

    def backup(self, name):
        """ benennt das als argument übergebene objekt im filesystem um """
        name_new = name + datetime.datetime.now().strftime(" - %Y%m%d-%H%M%S")
        try:
            log.debug(u"  … benenne %s nach %s um" % 
              (name.decode("utf-8"), name_new.decode("utf-8")))
            os.rename(name, name_new)
        except IOError:
            log.error(u"  … umbennen von %s nach %s ging schief" % 
              (name, name_new))
            sys.exit(1)

    def settings_from_file(self, what):
        """ liest einstellungen aus ini_file und schreibt sie in das profil """
        self.ini = ConfigParser.RawConfigParser()
        # mozilla ist case sensitive …
        self.ini.optionxform = str
        self.items = ""
        log.debug(u"    … lese einstellungen aus %s , abschnitt %s" % \
          (self.ini_file, what))
        try:
            if self.ini.read(self.ini_file):
                if self.ini.has_section(what):
                    log.trace(u"      … lese einstellungen in %s" % what)
                    if what == "mandatory":
                        force_settings = True
                    else:
                        force_settings = False
                    for self.item in self.ini.items(what):
                        self.set_value(*self.item, force = force_settings)
                else:
                    log.info("      … der abschnitt %s fehlt!" % what)
            else:
                log.error(u"    … datei %s ist nicht lesbar!" % self.ini_file)
                sys.exit(1)
        except Exception, e:
            log.error(u"    … fehler: %s" % e)
            sys.exit(1)

    def done(self):
        """ änderungen schreiben, falls nötig """
        if self.is_dirty:
            log.info(u"  … es gab änderungen, diese werden geschrieben")
            self.save_profile()
        else:
            log.info(u"  … keine zu schreibenden änderungen")

class tbprofile(mozprofile):
    """ profil für tunderbird """
    def __init__(self):
        log.info(u"… thunderbird:")
        self.profile_path = "Thunderbird\\"
        self.exe_path = "Mozilla Thunderbird\\thunderbird.exe"    
        self.ini_file = args.path_settings + "\\" + args.moz_tb_settings
        self.certs_wl = args.path_settings + "\\certs\\tb-whitelist"
        self.certs_bl = args.path_settings + "\\certs\\tb-blacklist"
        self.force_update = args.moz_tb_update
        self.content = {}

class ffprofile(mozprofile):
    """ profil für firefox """
    def __init__(self):
        log.info(u"… firefox:")
        self.profile_path = "Mozilla\\Firefox\\"
        self.exe_path = "Mozilla Firefox\\firefox.exe"    
        self.ini_file = args.path_settings + "\\" + args.moz_ff_settings
        self.certs_wl = args.path_settings + "\\certs\\ff-whitelist"
        self.certs_bl = args.path_settings + "\\certs\\ff-blacklist"
        self.force_update = args.moz_ff_update
        self.content = {}

    

### here we go …

# unicode für cmd-shell
kmt.utils.fix_cmd_unicode()
# logging ist schön
log = kmt.utils.setup_logger(tempfile.gettempdir() + "/" + 
  os.path.basename(__file__) + ".log")
log.info(u"… start")

#  default-werte klarmachen
try:
    logonserver = os.environ["LOGONSERVER"]
except KeyError:
    log.critical("… %LOGONSERVER% ist nicht definiert ?!")   
    sys.exit(1)
# logonserver = "//stone"
settings_path = logonserver + ".ad.kinemathek.de\\netlogon\\settings"
tools_path = logonserver + ".ad.kinemathek.de\\netlogon\\tools"
ff_settings = "firefox-settings.ini"
tb_settings = "thunderbird-settings.ini"
pw = ""

# cli-argumente parsen
args = setup_args()
if args.verbose == 1:
    log.setLevel(logging.DEBUG)
elif args.verbose > 1:
    log.setLevel(logging.TRACE)

if args.password:
    while pw == "":
        log.debug(u"… passwort-abfrage")
        get_password()

# okay, business. thunderbird …
tbp = tbprofile()
if not tbp.check_profile():
    tbp.create_profile()
if args.moz_tb_force:
    tbp.rename_profile()
    tbp.create_profile()
if tbp.is_new or args.moz_tb_update:
    if not pw:
        get_password()
    tbp.load_profile()
    tbp.update_profile("mandatory")
    if tbp.is_new:
        tbp.update_profile("optional")
tbp.done()

# firefox …
ffp = ffprofile()
if not ffp.check_profile():
    ffp.create_profile()
if args.moz_ff_force:
    ffp.rename_profile()
    ffp.create_profile()
if ffp.is_new or args.moz_ff_update:
    ffp.load_profile()
    ffp.update_profile("mandatory")
    if ffp.is_new:
        ffp.update_profile("optional")
ffp.done()


# print(ffp.get_value("browser.startup.homepage"))
# print(ffp.get_value("browser.download.debug"))
# ffp.set_value("browser.download.debug", "true")
# ffp.set_value("browser.startup.homepage", "\"http://www.xkcd.org\"", force=True)

# thunderbird …
# print(tbp.get_value("signon.debug"))
# print(tbp.get_value("mailnews.tags.$labe1.tag"))
# tbp.set_value("signon.debug", "true")
# tbp.set_value("mailnews.tags.$label1.tag", "\"scheißegal\"", force=True)

