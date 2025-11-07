#*******************************************************************************
#*   (c) 2019 Zondax GmbH
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************

# We use BOLOS_SDK to determine the development environment that is being used
# BOLOS_SDK IS  DEFINED	 	We use the plain Makefile for Ledger
# BOLOS_SDK NOT DEFINED		We use a containerized build approach

TESTS_JS_PACKAGE = "@zondax/ledger-oasis"
TESTS_JS_DIR = $(CURDIR)/js

ifeq ($(BOLOS_SDK),)
PRODUCTION_BUILD ?= 1
SKIP_NANOS = 1

ifeq ($(SKIP_NANOS), 0)
$(error "NanoS device is not supported")
endif

include $(CURDIR)/deps/ledger-zxlib/dockerized_build.mk

else
default:
	$(MAKE) -C app
%:
	$(info "Calling app Makefile for target $@")
	COIN=$(COIN) $(MAKE) -C app $@
endif

# Main test target called by CI
test_all:
	make
	make zemu_install
	make zemu_test

# Install test dependencies
.PHONY: zemu_install
zemu_install: zemu_install_js_link
	# Build native test tools
	cd tests_tools/neon && yarn install
	# Install test dependencies
	cd $(TESTS_ZEMU_DIR) && yarn install

# Run tests
zemu_test:
	cd tests_zemu && yarn test

# Helper targets for development
tests_tools_clean:
	rm -f tests_tools/neon/native/index.node
	rm -rf tests_tools/target
	cd tests_tools && cargo clean

tests_tools_rebuild: tests_tools_clean
	cd tests_tools/neon && yarn install