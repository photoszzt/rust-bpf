export KERNEL_BUILD_PATH := /lib/modules/$(shell uname -r)/build

all:
	STD_KERNEL_PATH='${KERNEL_BUILD_PATH}' cargo build

test:
	STD_KERNEL_PATH='${KERNEL_BUILD_PATH}' cargo test
