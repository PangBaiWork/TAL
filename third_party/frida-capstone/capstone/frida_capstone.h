#pragma once

#if defined(TAL_PLATFORM_ANDROID)
#include "../../android/frida/frida-gum.h"
#elif defined(TAL_PLATFORM_LINUX)
#include "../../linux/frida/frida-gum.h"
#elif defined(TAL_PLATFORM_WINDOWS)
#include "../../windows/frida/frida-gum.h"
#else
#error "Define one of TAL_PLATFORM_ANDROID, TAL_PLATFORM_LINUX, or TAL_PLATFORM_WINDOWS"
#endif
