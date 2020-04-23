# Ledger Oasis app
![stability-wip](https://img.shields.io/badge/stability-work_in_progress-lightgrey.svg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CircleCI](https://circleci.com/gh/Zondax/ledger-oasis/tree/master.svg?style=shield)](https://circleci.com/gh/Zondax/ledger-oasis/tree/master)
[![CodeFactor](https://www.codefactor.io/repository/github/zondax/ledger-oasis/badge)](https://www.codefactor.io/repository/github/zondax/ledger-oasis)

This repository contains:

- Ledger Nano S/X Oasis app
- Specs / Documentation
- C++ unit tests

## Prerequisites

**We strongly recommend using Linux as your development environment.**

### Ledger Nano S

- This project requires Ledger firmware 1.6

- The current repository keeps track of Ledger's SDK but it is possible to override it by changing the git submodule.

### System packages

Make sure you have the following system tools installed:
- git,
- Python 3 and pip,
- Make.

If you are on Ubuntu, use:
```
sudo apt update && sudo apt install git python3-pip make
```

If you are on Fedora, use:
```
sudo dnf install git-core python3-pip make
```

### Source

Apart from cloning, be sure you get all the submodules if you are building locally
```
git submodule update --init --recursive
```

### [Python tools for Ledger Blue, Nano S and Nano X]

First, install distribution-specific development packages:

- If you are on Ubuntu, use:

   ```
   sudo apt install libusb-1.0.0 libudev-dev
   ```
- If you are on Fedora, use:

   ```
   sudo dnf install libusbx-devel libudev-devel
   ```

Then install Python tools for Ledger Blue, Nano S and Nano X with:

```
pip install ledgerblue
```

[Python tools for Ledger Blue, Nano S and Nano X]: https://github.com/LedgerHQ/blue-loader-python

#### Docker CE

If you don't have a Ledger's SDK installed locally, the Ledger App will be built
in a container, so install Docker CE by following the instructions at
https://docs.docker.com/install/.

#### Local build/development dependencies

_NOTE: Only Ubuntu is supported for local building/development._

If you will be developing the Ledger App locally, install the following system packages:

```
sudo apt install build-essential wget cmake libssl-dev libgmp-dev autoconf libtool
```

You also need to install [Conan](https://conan.io/):

```bash
pip install conan
```

_Warning: Some IDEs may not use the same python interpreter or virtual enviroment as the one you used when running `pip`.
If you see conan is not found, check that you installed the package in the same interpreter as the one that launches `cmake`._

## Installation

At the moment, the only option is to build the app on your own. **Please only use a TEST DEVICE!**

Once the app is ready and we reach v1.0.0, it will be submitted to Ledger so it is published in the app Catalog.

## Prepare your development device

**Please do not use a Ledger device with funds for development purposes.**

**Have a second device that is used ONLY for development and testing**

There are a few additional steps that increase reproducibility and simplify development:

### 1. Ensure your device works in your OS

- In Linux hosts it might be necessary to adjust udev rules, etc. Refer to Ledger documentation: https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues

### 2. Set a test mnemonic

All our tests expect the device to be configured with a known test mnemonic.

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Double click

- Run `make dev_init`. This will take about 2 minutes. The device will be initialized to:

   ```
   PIN: 5555
   Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young
   ```

### 3. Add a development certificate

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Click both buttons at the same time

- Enter your pin if necessary

- Run `make dev_ca`. The device will receive a development certificate to avoid constant manual confirmations.

## Building the Ledger App

The Makefile will build the firmware in a docker container and leave the binary in the correct directory.

- Build

   The following command will build the app firmware inside a container and load to your device:
   ```
   make                # Builds the app
   ```

- Upload to a device

   The following command will upload the application to the ledger:

   _Warning: The application will be deleted before uploading._
   ```
   make load          # Builds and loads the app to the device
   ```

## Development (building C++ Code / Tests)

This is useful when you want to make changes to libraries, run unit tests, etc. It will build all common libraries and unit tests.

### Building unit tests

While we recommend you configure your preferred development environment, the minimum steps are as follows:

```
mkdir build
cd build
cmake .. && make
```

### Running unit tests

```
export GTEST_COLOR=1 && ctest -VV
```

## Specifications

- [APDU Protocol](https://github.com/zondax/ledger-oasis/tree/master/docs/APDUSPEC.md)
