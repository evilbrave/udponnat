#! /usr/bin/env python

#############################################################################
#                                                                           #
#   File: parseconf.py                                                      #
#                                                                           #
#   Copyright (C) 2008 Du XiaoGang <dugang@188.com>                         #
#                                                                           #
#   This file is part of UDPonNAT.                                          #
#                                                                           #
#   UDPonNAT is free software: you can redistribute it and/or modify        #
#   it under the terms of the GNU General Public License as                 #
#   published by the Free Software Foundation, either version 3 of the      #
#   License, or (at your option) any later version.                         #
#                                                                           #
#   UDPonNAT is distributed in the hope that it will be useful,             #
#   but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#   GNU General Public License for more details.                            #
#                                                                           #
#   You should have received a copy of the GNU General Public License       #
#   along with UDPonNAT.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                           #
#############################################################################

class ParseConfError(Exception):
    pass

class NameNotExisted(ParseConfError):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return '<Name Not Existed: %s>' % self.name

class DuplicatedSectionName(ParseConfError):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return '<Duplicated Section Name: %s>' % self.name

class SectionNotExisted(ParseConfError):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return '<Section Not Existed: %s>' % self.name

class ParseConf(object):
    '''Parse configuration file.'''
    def __init__(self, file):
        self.globalNVs = {}
        self.sections = {}

        curSection = None
        # read server.conf
        f = open(file, 'r')
        line = f.readline()
        while line != '':
            line = line.strip()
            if line != '' and not line.startswith('#'):
                # data line
                if line.startswith('['):
                    # new section
                    section = line[1:]
                    section = section.rpartition(']')[0]
                    section = section.strip()
                    if self.sections.has_key(section):
                        raise DuplicatedSectionName(section)
                    self.sections[section] = {}
                    curSection = section
                else:
                    (n, _, v) = line.partition('=')
                    n = n.strip()
                    v = v.strip()
                    if not curSection:
                        self.globalNVs[n] = v
                    else:
                        self.sections[curSection][n] = v
            # next line
            line = f.readline()
        f.close()

    def getValue(self, name, section=None):
        if not section:
            # global NV
            if not self.globalNVs.has_key(name):
                raise NameNotExisted(name)
            return self.globalNVs[name]
        else:
            # section NV
            if not self.sections.has_key(section):
                raise SectionNotExisted(section)
            if not self.sections[section].has_key(name):
                raise NameNotExisted(name)
            return self.sections[section][name]

    def enumerateSections(self):
        return self.sections.keys()
