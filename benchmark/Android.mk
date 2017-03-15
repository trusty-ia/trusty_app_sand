
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
    main.c \
    rsa_test.c \
    benchmarks.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_SHARED_LIBRARIES := libhardware libcrypto

LOCAL_CFLAGS += -g -O2 -std=gnu99 \
    -DBUILD_FOR_ANDROID

LOCAL_MODULE := benchmark

#LOCAL_MULTILIB := both
#LOCAL_MODULE_STEM_32 := $(LOCAL_MODULE)32
LOCAL_MODULE_STEM_64 := $(LOCAL_MODULE)64

LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
include $(BUILD_EXECUTABLE)
