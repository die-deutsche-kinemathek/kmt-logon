#! /usr/bin/env python
# -*- coding: utf-8 -*-

""" verwaltung von thunderbird- und firefox-profilen """

class user_profile:
    """ basis-klasse für das user-profil """
    def __init__(self):
        """ initialisierung - win32-konsole unicode-fähig machen"""
        win_console_fixes.do_fix()

    def hw(self):
        print "hellooo … äöü ☭"
