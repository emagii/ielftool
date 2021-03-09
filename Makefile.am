AUTOMAKE_OPTIONS        = foreign nostdinc subdir-objects

ACLOCAL_AMFLAGS         = -I m4

AM_CFLAGS               = 
AM_LDFLAGS              = $(LIBS)
AM_CPPFLAGS =           -I$(top_builddir) \
                        -I$(top_srcdir) \
                          $(DEP_CFLAGS)
AM_CPPFLAGS             += $(CPPFLAGS)

LIB_CFLAGS              = $(LIBS)

bin_PROGRAMS            = ielftool
sysconf_DATA            = 
AM_CFLAGS               += -Wall
CLEANFILES              = 


VERSION_INFO            = -version-info 0:0:0

if CONFIG_OS_LINUX
AM_CFLAGS               += -DOS_LINUX
endif


if USE_PTHREAD
AM_CFLAGS               += -pthread
LIB_CFLAGS              += $(PTHREAD_CFLAGS)
endif


AM_CFLAGS               += $(LIB_CFLAGS)
AM_CFLAGS               += -Isrc
AM_CFLAGS               += -Isrc/include
AM_CFLAGS               += -Iinclude

ielftool_LDFLAGS        = $(AM_LDFLAGS)
ielftool_CFLAGS         = $(AM_CFLAGS)
ielftool_CPPFLAGS       = $(AM_CPPFLAGS)
ielftool_LDAPP          = $(LIB_CFLAGS)
# 'csource+headers-am.inc' provides the CSOURCES, HHEADERS and INSTALL_HEADERS defines
CSOURCES = \
	src/LxElfChecksumCmd.cpp	\
	src/LxElfCmd.cpp		\
	src/LxElfCmdFactory.cpp		\
	src/LxElfDataBuffer.cpp		\
	src/LxElfEntrySteerFile.cpp	\
	src/LxElfException.cpp		\
	src/LxElfFile.cpp		\
	src/LxElfFillCmd.cpp		\
	src/LxElfFrontCmd.cpp		\
	src/LxElfRelocCmd.cpp		\
	src/LxElfSaveBinCmd.cpp		\
	src/LxElfSaveCmdBase.cpp	\
	src/LxElfSaveCmd.cpp		\
	src/LxElfSaveIHexCmd.cpp	\
	src/LxElfSaveSimpleCode.cpp	\
	src/LxElfSaveSRecCmd.cpp	\
	src/LxElfSaveTiTxtCmd.cpp	\
	src/LxElfStripCmd.cpp		\
	src/LxMain.cpp			\
	src/unicode_output.cpp

# INSTALL_HEADERS = 

# Config needs to have a separate recipe
# INSTALL_CONFIG = 

HHEADERS = \
	$(INSTALL_HEADERS)		\
	src/BuildTxt.h			\
	src/IARTPVersion.h		\
	src/LxElfChecksumCmd.h		\
	src/LxElfCmdFactory.h		\
	src/LxElfCmd.h			\
	src/LxElfDataBuffer.h		\
	src/LxElfEntrySteerFile.h	\
	src/LxElfException.h		\
	src/LxElfFile.h			\
	src/LxElfFillCmd.h		\
	src/LxElfFrontCmd.h		\
	src/LxElfParityCmd.h		\
	src/LxElfRelocCmd.h		\
	src/LxElfSaveBinCmd.h		\
	src/LxElfSaveCmdBase.h		\
	src/LxElfSaveCmd.h		\
	src/LxElfSaveIHexCmd.h		\
	src/LxElfSaveSimpleCode.h	\
	src/LxElfSaveSRecCmd.h		\
	src/LxElfSaveTiTxtCmd.h		\
	src/LxElfStripCmd.h		\
	src/LxElfTypes.h		\
	src/LxMain.h			\
	src/LxOutput.h			\
	src/unicode_output.h		\
	src/IARTPVersion.h		\
	src/BuildTxt.h			\
	windows/afxres.h		\
	windows/windows.h

# Demos needs to have a separate recipe
# INSTALL_DEMOS =


ielftool_SOURCES        = $(CSOURCES) $(HHEADERS)
clean-local:
