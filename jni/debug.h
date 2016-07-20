#ifndef __FPS_INJECT_DEBUG__
#define __FPS_INJECT_DEBUG__

#include <jni.h>

#define ENABLE_DEBUG 0

#if ENABLE_DEBUG

#define  LOG_TAG "FPS"
#define LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define LOGE(fmt, args...)  __android_log_print(ANDROID_LOG_ERROR,LOG_TAG, fmt, ##args)
#define DEBUG_PRINT(format,args...) LOGD(format, ##args)

#else

#define DEBUG_PRINT(format,args...)
#define LOGD(fmt, args...)
#define LOGE(fmt, args...)
#endif


#endif /* __FPS_INJECT_DEBUG__ */
