LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := jnetpcap

LOCAL_SRC_FILES :=\
    jnetpcap.cpp\
    packet_flow.cpp\
    packet_jheader.cpp\
    jnetpcap_pcap_header.cpp\
    nio_jbuffer.cpp\
    winpcap_stat_ex.cpp\
    winpcap_send_queue.cpp\
    winpcap_ext.cpp\
    jnetpcap_ids.cpp\
    jnetpcap_dumper.cpp\
    jnetpcap_utils.cpp\
    util_in_cksum.cpp\
    jnetpcap_beta.cpp\
    nio_jmemory.cpp\
    packet_jsmall_scanner.cpp\
    packet_protocol.cpp\
    nio_jnumber.cpp\
    packet_jheader_scanner.cpp\
    packet_jscan.cpp\
    util_checksum.cpp\
    packet_jpacket.cpp\
    winpcap_ids.cpp\
    util_debug.cpp\
    util_crc16.c\
    util_crc32.c\
    jnetpcap_bpf.cpp

LOCAL_C_INCLUDES :=\
	$(NDK_ROOT)/platforms/android-8/arch-arm/usr/include\
	$(LOCAL_PATH)/libpcap

LOCAL_CFLAGS := -DLIBPCAP_VERSION=0x097

LOCAL_STATIC_LIBRARIES := libpcap

include $(BUILD_SHARED_LIBRARY)

include $(LOCAL_PATH)/libpcap/Android.mk
