.. zephyr:code-sample:: usb-fido2
   :name: USB FIDO2 authenticator
   :relevant-api: fido2

   Demonstrate the work-in-progress FIDO2 authenticator subsystem over USB HID.

Overview
********

This sample initializes the FIDO2 authenticator subsystem and exposes the
CTAPHID transport as a USB HID interface. It is intended for exercising the
work-in-progress implementation in :zephyr_file:`include/zephyr/authentication/fido2`
and :zephyr_file:`subsys/authentication/fido2`.

The current subsystem can enumerate as a FIDO2 HID device and handle
``authenticatorGetInfo``, ``authenticatorMakeCredential``, and
``authenticatorGetAssertion``/``authenticatorGetNextAssertion``.

By default, the sample falls back to the volatile FIDO2 storage backend. This
lets the application build on boards that do not define a
``zephyr,settings-partition`` or ``storage_partition``. With the volatile
backend, credentials and credential keys are stored in RAM and are lost on reset
or power-cycle.

The ``stm32f4_disco`` and ``stm32f746g_disco`` sample board configurations
enable persistent storage. They store credentials in the Zephyr settings
subsystem and store credential keys as persistent PSA keys, so credentials
survive a board reset. The sample uses the ZMS settings backend for these
boards. On ``stm32f4_disco`` storage is placed in the last two 128 KiB internal
flash sectors. On ``stm32f746g_disco`` storage uses the board-provided QSPI NOR
``storage_partition``.

Building and Running
********************

Build for the STM32F4 Discovery board:

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/usb/fido2
   :board: stm32f4_disco
   :goals: build
   :compact:

The sample also builds for the STM32F746G Discovery board:

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/usb/fido2
   :board: stm32f746g_disco
   :goals: build
   :compact:

Flash with OpenOCD:

.. code-block:: console

   west flash --runner openocd

Monitor the board UART at 115200 baud. For example:

.. code-block:: console

   picocom -b 115200 /dev/ttyUSB2

Testing with libfido2
*********************

The examples below use the ``fido2-token``, ``fido2-cred``, and
``fido2-assert`` command line tools from libfido2. After flashing the sample,
find the HID device node:

.. code-block:: console

   fido2-token -L

The token should appear as a Zephyr FIDO2 sample device, for example:

.. code-block:: none

   /dev/hidraw2: vendor=0x2fe3, product=0x0012 (Zephyr Project Zephyr FIDO2 Sample)

Set a shell variable for the device path shown on your host:

.. code-block:: console

   export FIDO2_DEV=/dev/hidraw2

Probe the token:

.. code-block:: console

   fido2-token -I ${FIDO2_DEV}

Create a credential. The input file contains a 32-byte client data hash, relying
party ID, user name, and 32-byte user ID:

.. code-block:: console

   printf '%s\n%s\n%s\n%s\n' \
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
     zephyr.example \
     zephyr-user \
     AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA= > cred_param

   fido2-cred -M -q -i cred_param ${FIDO2_DEV} es256 > cred_att
   fido2-cred -V -i cred_att -o cred_key es256

Get and verify an assertion using the credential ID returned by
``fido2-cred -V``:

.. code-block:: console

   printf '%s\n%s\n' \
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
     zephyr.example > assert_param
   head -1 cred_key >> assert_param

   fido2-assert -G -p -i assert_param ${FIDO2_DEV} > assert
   fido2-assert -V -p -i assert cred_key es256

All commands should exit with status 0. On ``stm32f4_disco`` and
``stm32f746g_disco``, credentials and keys are stored in non-volatile storage,
so the assertion test can still be run after resetting or power-cycling the
board. On boards that use the default RAM backend, run the credential creation
step again after every reset.

Storage Configuration
*********************

The common sample configuration does not require flash storage and selects the
RAM backend unless a board configuration enables another backend. This is useful
for boards that expose USB HID but do not have a storage partition available.

To enable persistent credentials for another board, add a board-specific
``boards/<board>.overlay`` that defines ``zephyr,settings-partition`` and add a
matching board configuration fragment, such as ``boards/<board>_<soc>.conf`` for
qualified board targets, that enables:

.. code-block:: none

   CONFIG_FIDO2_STORAGE_SETTINGS=y
   CONFIG_FLASH=y
   CONFIG_FLASH_MAP=y
   CONFIG_ZMS=y
   CONFIG_SETTINGS=y
   CONFIG_SETTINGS_ZMS=y
   CONFIG_SETTINGS_ZMS_FORCE_MOUNT=y
   CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS=y

Resident Credential Test
========================

Create two resident credentials for the same relying party:

.. code-block:: console

   printf '%s\n%s\n%s\n%s\n' \
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
     zephyr.example \
     alice \
     AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA= > cred_alice

   printf '%s\n%s\n%s\n%s\n' \
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
     zephyr.example \
     bob \
     AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICE= > cred_bob

   fido2-cred -M -r -q -i cred_alice ${FIDO2_DEV} es256 > cred_alice_att
   fido2-cred -M -r -q -i cred_bob ${FIDO2_DEV} es256 > cred_bob_att

Request an assertion without an allow list:

.. code-block:: console

   printf '%s\n%s\n' \
     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
     zephyr.example > assert_resident_param

   fido2-assert -G -p -r -i assert_resident_param ${FIDO2_DEV} > assert_resident

The output should contain two assertion records. This exercises
``authenticatorGetAssertion`` followed by ``authenticatorGetNextAssertion``.
