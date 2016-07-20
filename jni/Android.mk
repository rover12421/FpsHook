LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog -lEGL

LOCAL_MODULE    := FpsShow
LOCAL_SRC_FILES := FpsShow.c
include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)

LOCAL_MODULE    := infps
LOCAL_SRC_FILES := inject.c

LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog
#LOCAL_CFLAGS += -fpermissive

include $(BUILD_EXECUTABLE)
