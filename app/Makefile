#*******************************************************************************
#  Ledger App
#  (c) 2018 - 2022 Zondax GmbH
#  (c) 2017 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error BOLOS_SDK is not set)
endif

MY_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.installer_script

include $(BOLOS_SDK)/Makefile.defines

# Set the default value for PRODUCTION_BUILD to 1 if not already defined
PRODUCTION_BUILD ?= 1

$(info ************ OASIS_NAME  = [$(TARGET_NAME)])

# Display whether this is a production build or for internal use
ifeq ($(PRODUCTION_BUILD), 1)
    $(info ************ PRODUCTION_BUILD  = [PRODUCTION BUILD])
else
    $(info ************ PRODUCTION_BUILD  = [INTERNAL USE])
endif

DEFINES += PRODUCTION_BUILD=$(PRODUCTION_BUILD)

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.app_testing

ifndef COIN
COIN=oasis
endif

include $(CURDIR)/Makefile.version

$(info COIN  = [$(COIN)])

ifeq ($(COIN),oasis)
# Main app configuration
DEFINES += APP_CONSUMER
APPNAME = "Oasis"
APPPATH = "44'/474'" --path "44'/60'" --path "44'/354'"
APPCURVE = --curve ed25519 --curve secp256k1
else ifeq ($(COIN),oasis_validator)
DEFINES += APP_VALIDATOR
APPNAME = "OasisVal"
APPPATH = "43'/474'"
APPCURVE = --curve ed25519

ifneq ($(TARGET_NAME),TARGET_NANOS)
$(error "Oasis Validator App only available for Nano S")
endif

else
define error_message


COIN value not supported: [$(COIN)]


endef
$(error "$(error_message)")
endif

APP_LOAD_PARAMS = $(APPCURVE) $(COMMON_LOAD_PARAMS) --path ${APPPATH}

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.devices
DEFINES += HAVE_INSPECT

$(info TARGET_NAME  = [$(TARGET_NAME)])
$(info ICONNAME  = [$(ICONNAME)])

ifndef ICONNAME
$(error ICONNAME is not set)
endif

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.platform
LDFLAGS += -z muldefs
APP_SOURCE_PATH += $(MY_DIR)/src
APP_SOURCE_PATH += $(MY_DIR)/../deps/ledger-zxlib/include
APP_SOURCE_PATH += $(MY_DIR)/../deps/ledger-zxlib/src
APP_SOURCE_PATH += $(MY_DIR)/../deps/ledger-zxlib/app/common
APP_SOURCE_PATH += $(MY_DIR)/../deps/ledger-zxlib/app/ui
APP_SOURCE_PATH += $(MY_DIR)/../deps/sha512

# NanoX SDK does not allow += in APP_SOURCE_PATH or INCLUDES_PATH
CFLAGS += -I$(MY_DIR)/../deps/tinycbor/src
APP_SOURCE_PATH += $(MY_DIR)/../deps/tinycbor-ledger

APP_CUSTOM_LINK_DEPENDENCIES = rust
LDLIBS += -Lrust/target/thumbv6m-none-eabi/release -lrslib
APP_SOURCE_PATH += $(CURDIR)/rust/include

.PHONY: rust
rust:
	cd rust && RUSTC_BOOTSTRAP=1 CARGO_HOME="$(CURDIR)/rust/.cargo" cargo build --target thumbv6m-none-eabi --release

# Before linking, we need to be sure rust lib is there
bin/app.elf: rust

.PHONY: rust_clean
rust_clean:
	cd rust && CARGO_HOME="$(CURDIR)/rust/.cargo" cargo clean

clean: rust_clean

include $(CURDIR)/../deps/ledger-zxlib/makefiles/Makefile.side_loading

# Import generic rules from the SDK
include $(BOLOS_SDK)/Makefile.rules

#add dependency on custom makefile filename
dep/%.d: %.c Makefile

.PHONY: listvariants
listvariants:
ifeq ($(TARGET_NAME),TARGET_NANOS)
	@echo VARIANTS COIN oasis oasis_validator
else
	@echo VARIANTS COIN oasis
endif

.PHONY: version
version:
	@echo "v$(APPVERSION)" > app.version
