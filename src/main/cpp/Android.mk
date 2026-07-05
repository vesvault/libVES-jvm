# libves-jvm native build.
#
# Builds two shared libraries:
#   libVES.so      — libVES.c core, compiled from the libVES.c submodule
#   libVESjni.so   — JNI shim that exposes libVES via the Java API
#
# Static prebuilts for OpenSSL, libcurl, and liboqs are expected under
# $(JNI_DIR)/deps/<lib>/<TARGET_ARCH_ABI>/. On the build host, symlink:
#   src/main/cpp/deps -> /usr/src/vesmail-android/jni/deps

JNI_DIR     := $(call my-dir)
LIBVES_ROOT := $(JNI_DIR)/../../../libVES.c
LIBVES_LIB  := $(LIBVES_ROOT)/lib

DEPS        := $(JNI_DIR)/deps
INC_OPENSSL := $(DEPS)/openssl/$(TARGET_ARCH_ABI)/include
LIB_CRYPTO  := $(DEPS)/openssl/$(TARGET_ARCH_ABI)/lib/libcrypto.a
LIB_SSL     := $(DEPS)/openssl/$(TARGET_ARCH_ABI)/lib/libssl.a
INC_CURL    := $(DEPS)/curl/$(TARGET_ARCH_ABI)/include
LIB_CURL    := $(DEPS)/curl/$(TARGET_ARCH_ABI)/lib/libcurl.a
INC_OQS     := $(DEPS)/liboqs/$(TARGET_ARCH_ABI)/include
LIB_OQS     := $(DEPS)/liboqs/$(TARGET_ARCH_ABI)/lib/liboqs.a


# libVES.so — built from the libVES.c submodule.
include $(CLEAR_VARS)
LOCAL_PATH := $(LIBVES_LIB)
LOCAL_MODULE := libVES
LOCAL_MODULE_FILENAME := libVES
# -DHAVE_LIBOQS enables the post-quantum (ML-KEM / OQS) dispatch in
# KeyAlgo_EVP.c and VaultKey.c. Without it the OQS sources still compile and
# liboqs is still linked, but libVES_KeyAlgo_OQS is left out of the algo list
# and defaultAlgo() falls back to ECDH — i.e. the .aar cannot use PQ keys
# despite "post-quantum by default". The autotools build sets this via config.h.
LOCAL_CFLAGS += -I$(INC_OPENSSL) -I$(INC_CURL) -I$(INC_OQS) \
    -DOPENSSL_API_COMPAT=0x10100000L -DHAVE_LIBOQS
# tls_root.c lives in the JNI dir (out of the submodule tree) but is compiled
# into libVES.so so it can reach the library-local curl symbols.
LOCAL_C_INCLUDES += $(LIBVES_LIB)
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true
LOCAL_WHOLE_STATIC_LIBRARIES += libcurl libcrypto libssl liboqs
LOCAL_LDLIBS += -lz
LOCAL_SRC_FILES := \
    libVES.c \
    VESflow.c \
    VESlocker.c \
    libVES/Util.c \
    libVES/List.c \
    libVES/Cipher.c \
    libVES/CiAlgo_AES.c \
    libVES/VaultKey.c \
    libVES/KeyAlgo_EVP.c \
    libVES/KeyAlgo_OQS.c \
    libVES/VaultItem.c \
    libVES/Ref.c \
    libVES/User.c \
    libVES/File.c \
    libVES/REST.c \
    libVES/KeyStore.c \
    libVES/Event.c \
    libVES/Flow.c \
    libVES/Session.c \
    libVES/Watch.c \
    jVar.c \
    ../../src/main/cpp/tls_root.c
include $(BUILD_SHARED_LIBRARY)


# libVESjni.so — the JNI shim.
include $(CLEAR_VARS)
LOCAL_PATH := $(JNI_DIR)
LOCAL_MODULE := libVESjni
LOCAL_MODULE_FILENAME := libVESjni
LOCAL_CFLAGS += -I$(LIBVES_LIB) -I$(JNI_DIR)/include -I$(INC_OPENSSL)
LOCAL_SHARED_LIBRARIES += libVES
LOCAL_SRC_FILES := \
    jni_libves.c \
    jni_util.c \
    jni_vault.c \
    jni_item.c \
    jni_itemcipher.c \
    jni_jvar.c \
    jni_veslocker.c \
    jni_vesflow.c \
    jni_watch.c
include $(BUILD_SHARED_LIBRARY)


# Prebuilt static deps.
include $(CLEAR_VARS)
LOCAL_PATH := $(JNI_DIR)
LOCAL_MODULE := libcrypto
LOCAL_SRC_FILES := $(LIB_CRYPTO)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_PATH := $(JNI_DIR)
LOCAL_MODULE := libssl
LOCAL_SRC_FILES := $(LIB_SSL)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_PATH := $(JNI_DIR)
LOCAL_MODULE := libcurl
LOCAL_SRC_FILES := $(LIB_CURL)
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_PATH := $(JNI_DIR)
LOCAL_MODULE := liboqs
LOCAL_SRC_FILES := $(LIB_OQS)
include $(PREBUILT_STATIC_LIBRARY)
