# Makefile for Wazuh API
# Copyright (C) 2015-2020, Wazuh Inc.
# May 3, 2017
#
# Syntax: make [ all | install]

OSSEC_GROUP       = ossec
PREFIX            = /var/ossec

RM_FILE        = rm -f
INSTALL_DIR    = install -o root -g ${OSSEC_GROUP} -m 0750 -d
INSTALL_RW_DIR = install -o root -g ${OSSEC_GROUP} -m 0770 -d
INSTALL_EXEC   = install -o root -g ${OSSEC_GROUP} -m 0750
INSTALL_FILE   = install -o root -g ${OSSEC_GROUP} -m 0640
INSTALL_CONFIG_FILE   = install -o root -g ${OSSEC_GROUP} -m 0660
PYTHON_BIN     = $(PREFIX)/framework/python/bin/python3


.PHONY: all install service

all: install service

install:
    # Backup previous configuration
	. ../api/service/inst-api-functions.sh; backup_old_api

    # Copy files and create folders
	$(INSTALL_DIR) $(PREFIX)/api
	$(INSTALL_RW_DIR) $(PREFIX)/api/configuration
	$(INSTALL_RW_DIR) $(PREFIX)/api/configuration/ssl
	$(INSTALL_RW_DIR) $(PREFIX)/api/configuration/security

	$(INSTALL_CONFIG_FILE) api/configuration/api.yaml ${PREFIX}/api/configuration

	$(INSTALL_DIR) $(PREFIX)/api/scripts
	$(INSTALL_FILE) scripts/wazuh-apid.py ${PREFIX}/api/scripts

	$(INSTALL_DIR) $(PREFIX)/api/service
	$(INSTALL_EXEC) service/wazuh-api $(PREFIX)/api/service
	$(INSTALL_EXEC) service/wazuh-api.service $(PREFIX)/api/service
	$(INSTALL_EXEC) service/install_daemon.sh $(PREFIX)/api/service

    # Install scripts/%.py on $(PREFIX)/bin/%
	$(foreach script,$(wildcard scripts/*),$(INSTALL_EXEC) wrappers/generic_wrapper.sh $(patsubst scripts/%.py,$(PREFIX)/bin/%,$(script));)

    # Restore old API config
	. ../api/service/inst-api-functions.sh; restore_old_api

    # Install daemon
service:
	WAZUH_PATH=$(PREFIX) $(PREFIX)/api/service/install_daemon.sh
