LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS := \
	$(LOCAL_DIR)/manifest.c \
	$(LOCAL_DIR)/main.cpp

MODULE_DEPS += \
	app/trusty \
	lib/libc-trusty \
	lib/libstdc++-trusty \
	lib/tinyxml2

MODULE_INCLUDES := \
    $(LOCAL_DIR)/include

include make/module.mk
