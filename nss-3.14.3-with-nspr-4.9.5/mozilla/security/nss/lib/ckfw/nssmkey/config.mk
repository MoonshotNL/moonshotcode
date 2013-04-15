# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
CONFIG_CVS_ID = "@(#) $RCSfile: config.mk,v $ $Revision: 1.2 $ $Date: 2012/04/25 14:49:40 $"

ifdef BUILD_IDG
DEFINES += -DNSSDEBUG
endif

ifdef NS_USE_CKFW_TRACE
DEFINES += -DTRACE
endif

#
#  Override TARGETS variable so that only static libraries
#  are specifed as dependencies within rules.mk.
#

TARGETS        = $(LIBRARY)
SHARED_LIBRARY =
IMPORT_LIBRARY =
PROGRAM        =


