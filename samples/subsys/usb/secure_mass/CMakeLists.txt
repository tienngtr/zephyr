cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(secure_mass)

target_sources(app PRIVATE
	src/main.c
	src/secure_mass_button.c
	src/secure_mass_hid.c
	src/secure_mass_msc.c
	src/secure_mass_usb.c
)
