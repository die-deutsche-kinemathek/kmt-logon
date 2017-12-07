#! /usr/bin/env python
# -*- coding: utf-8 -*-

""" macht die beknackte windows-konsole halbwegs unicode-fähig
    von http://stackoverflow.com/questions/878972/windows-cmd-encoding-change-causes-python-crash/3259271#3259271 """

import sys, logging, tempfile, ConfigParser

def fix_cmd_unicode():
    if sys.platform == "win32":
        import codecs
        from ctypes import WINFUNCTYPE, windll, POINTER, byref, c_int
        from ctypes.wintypes import BOOL, HANDLE, DWORD, LPWSTR, LPCWSTR, LPVOID

        original_stderr = sys.stderr

        # If any exception occurs in this code, we'll probably try to print it on stderr,
        # which makes for frustrating debugging if stderr is directed to our wrapper.
        # So be paranoid about catching errors and reporting them to original_stderr,
        # so that we can at least see them.
        def _complain(message):
            print >>original_stderr, message if isinstance(message, str) else repr(message)

        # Work around <http://bugs.python.org/issue6058>.
        codecs.register(lambda name: codecs.lookup('utf-8') if name == 'cp65001' else None)

        # Make Unicode console output work independently of the current code page.
        # This also fixes <http://bugs.python.org/issue1602>.
        # Credit to Michael Kaplan <http://blogs.msdn.com/b/michkap/archive/2010/04/07/9989346.aspx>
        # and TZOmegaTZIOY
        # <http://stackoverflow.com/questions/878972/windows-cmd-encoding-change-causes-python-crash/1432462#1432462>.
        try:
            # <http://msdn.microsoft.com/en-us/library/ms683231(VS.85).aspx>
            # HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
            # returns INVALID_HANDLE_VALUE, NULL, or a valid handle
            #
            # <http://msdn.microsoft.com/en-us/library/aa364960(VS.85).aspx>
            # DWORD WINAPI GetFileType(DWORD hFile);
            #
            # <http://msdn.microsoft.com/en-us/library/ms683167(VS.85).aspx>
            # BOOL WINAPI GetConsoleMode(HANDLE hConsole, LPDWORD lpMode);

            GetStdHandle = WINFUNCTYPE(HANDLE, DWORD)(("GetStdHandle", windll.kernel32))
            STD_OUTPUT_HANDLE = DWORD(-11)
            STD_ERROR_HANDLE = DWORD(-12)
            GetFileType = WINFUNCTYPE(DWORD, DWORD)(("GetFileType", windll.kernel32))
            FILE_TYPE_CHAR = 0x0002
            FILE_TYPE_REMOTE = 0x8000
            GetConsoleMode = WINFUNCTYPE(BOOL, HANDLE, POINTER(DWORD))(("GetConsoleMode", windll.kernel32))
            INVALID_HANDLE_VALUE = DWORD(-1).value

            def not_a_console(handle):
                if handle == INVALID_HANDLE_VALUE or handle is None:
                    return True
                return ((GetFileType(handle) & ~FILE_TYPE_REMOTE) != FILE_TYPE_CHAR
                        or GetConsoleMode(handle, byref(DWORD())) == 0)

            old_stdout_fileno = None
            old_stderr_fileno = None
            if hasattr(sys.stdout, 'fileno'):
                old_stdout_fileno = sys.stdout.fileno()
            if hasattr(sys.stderr, 'fileno'):
                old_stderr_fileno = sys.stderr.fileno()

            STDOUT_FILENO = 1
            STDERR_FILENO = 2
            real_stdout = (old_stdout_fileno == STDOUT_FILENO)
            real_stderr = (old_stderr_fileno == STDERR_FILENO)

            if real_stdout:
                hStdout = GetStdHandle(STD_OUTPUT_HANDLE)
                if not_a_console(hStdout):
                    real_stdout = False

            if real_stderr:
                hStderr = GetStdHandle(STD_ERROR_HANDLE)
                if not_a_console(hStderr):
                    real_stderr = False

            if real_stdout or real_stderr:
                # BOOL WINAPI WriteConsoleW(HANDLE hOutput, LPWSTR lpBuffer, DWORD nChars,
                #                           LPDWORD lpCharsWritten, LPVOID lpReserved);

                WriteConsoleW = WINFUNCTYPE(BOOL, HANDLE, LPWSTR, DWORD, POINTER(DWORD), LPVOID)(("WriteConsoleW", windll.kernel32))

                class UnicodeOutput:
                    def __init__(self, hConsole, stream, fileno, name):
                        self._hConsole = hConsole
                        self._stream = stream
                        self._fileno = fileno
                        self.closed = False
                        self.softspace = False
                        self.mode = 'w'
                        self.encoding = 'utf-8'
                        self.name = name
                        self.flush()

                    def isatty(self):
                        return False

                    def close(self):
                        # don't really close the handle, that would only cause problems
                        self.closed = True

                    def fileno(self):
                        return self._fileno

                    def flush(self):
                        if self._hConsole is None:
                            try:
                                self._stream.flush()
                            except Exception as e:
                                _complain("%s.flush: %r from %r" % (self.name, e, self._stream))
                                raise

                    def write(self, text):
                        try:
                            if self._hConsole is None:
                                if isinstance(text, unicode):
                                    text = text.encode('utf-8')
                                self._stream.write(text)
                            else:
                                if not isinstance(text, unicode):
                                    text = str(text).decode('utf-8')
                                remaining = len(text)
                                while remaining:
                                    n = DWORD(0)
                                    # There is a shorter-than-documented limitation on the
                                    # length of the string passed to WriteConsoleW (see
                                    # <http://tahoe-lafs.org/trac/tahoe-lafs/ticket/1232>.
                                    retval = WriteConsoleW(self._hConsole, text, min(remaining, 10000), byref(n), None)
                                    if retval == 0 or n.value == 0:
                                        raise IOError("WriteConsoleW returned %r, n.value = %r" % (retval, n.value))
                                    remaining -= n.value
                                    if not remaining:
                                        break
                                    text = text[n.value:]
                        except Exception as e:
                            _complain("%s.write: %r" % (self.name, e))
                            raise

                    def writelines(self, lines):
                        try:
                            for line in lines:
                                self.write(line)
                        except Exception as e:
                            _complain("%s.writelines: %r" % (self.name, e))
                            raise

                if real_stdout:
                    sys.stdout = UnicodeOutput(hStdout, None, STDOUT_FILENO, '<Unicode console stdout>')
                else:
                    sys.stdout = UnicodeOutput(None, sys.stdout, old_stdout_fileno, '<Unicode redirected stdout>')

                if real_stderr:
                    sys.stderr = UnicodeOutput(hStderr, None, STDERR_FILENO, '<Unicode console stderr>')
                else:
                    sys.stderr = UnicodeOutput(None, sys.stderr, old_stderr_fileno, '<Unicode redirected stderr>')
        except Exception as e:
            _complain("exception %r while fixing up sys.stdout and sys.stderr" % (e,))


def setup_logger(fn="", log_instance="kmt-logon"):
    """ logging auf der console und in ein logfile, argument: name des
        logfiles """
    # zusätzlicher log-level "trace"
    logging.TRACE = 5
    logging.addLevelName(logging.TRACE, "TRACE")
    def trace(self, message, *args, **kws):
        if self.isEnabledFor(logging.TRACE):
            self._log(logging.TRACE, message, args, **kws) 
    logging.Logger.trace = trace
    # unsere instanz
    logger = logging.getLogger(log_instance)
    format =  logging.Formatter(
      "%(asctime)s - %(name)s - %(levelname)7s - %(message)s")
    # console
    ch = logging.StreamHandler()
    ch.setFormatter(format)
    logger.addHandler(ch)
    # logfile
    if fn == "":
        fn = tempfile.gettempdir() + "/kmt_log.log"
    fh = logging.FileHandler(fn, encoding = "UTF-8")
    fh.setFormatter(format)
    logger.addHandler(fh)
    logger.setLevel(logging.INFO)
    return logger

class kmt_configparser(ConfigParser.ConfigParser):
    """ das mozilla-zeugs mag " = " sowas in den profile.ini-dateien nicht.
        das hier ist der fix für python2, inspiriert von https://stackoverflow.com/questions/28090568/configparser-without-whitespace-surrounding-operator
        """
    def write(self, fp):
        if self._defaults:
            fp.write("[%s]\n" % DEFAULTSECT)
            for (key, value) in self._defaults.items():
                fp.write("%s = %s\n" % (key, str(value).replace('\n', '\n\t')))
            fp.write("\n")
        for section in self._sections:
            fp.write("[%s]\n" % section)
            for (key, value) in self._sections[section].items():
                if key == "__name__":
                    continue
                if (value is not None) or (self._optcre == self.OPTCRE):
                    # This is the important departure from ConfigParser for
                    # what you are looking for
                    key = "=".join((key, str(value).replace('\n', '\n\t')))
                fp.write("%s\n" % (key))
            fp.write("\n")
