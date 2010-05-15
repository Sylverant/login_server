#  
#   This file is part of Sylverant PSO Server.
#  
#   Copyright (C) 2009 Lawrence Sebald
#  
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 3 as
#   published by the Free Software Foundation.
#  
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#  
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4

LIBS += $(MYSQL_LIBS) $(LIBICONV)

bin_PROGRAMS = login_server
login_server_SOURCES = src/dclogin.c src/login.c src/login.h \
                       src/login_packets.c src/login_packets.h \
                       src/login_server.c

datarootdir = @datarootdir@

EXTRA_DIST = config.rpath
SUBDIRS = l10n
