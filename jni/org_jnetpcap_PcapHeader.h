/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_jnetpcap_PcapHeader */

#ifndef _Included_org_jnetpcap_PcapHeader
#define _Included_org_jnetpcap_PcapHeader
#ifdef __cplusplus
extern "C" {
#endif
/* Inaccessible static: directMemory */
/* Inaccessible static: directMemorySoft */
#undef org_jnetpcap_PcapHeader_MAX_DIRECT_MEMORY_DEFAULT
#define org_jnetpcap_PcapHeader_MAX_DIRECT_MEMORY_DEFAULT 67108864LL
/* Inaccessible static: POINTER */
#undef org_jnetpcap_PcapHeader_LENGTH
#define org_jnetpcap_PcapHeader_LENGTH 16L
/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_sizeof
  (JNIEnv *, jclass);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_len
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_hdr_1len__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_len
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1len__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_sec
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_PcapHeader_hdr_1sec__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_sec
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1sec__J
  (JNIEnv *, jobject, jlong);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_usec
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_hdr_1usec__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_usec
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1usec__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_wirelen
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_PcapHeader_hdr_1wirelen__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_PcapHeader
 * Method:    hdr_wirelen
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapHeader_hdr_1wirelen__I
  (JNIEnv *, jobject, jint);

#ifdef __cplusplus
}
#endif
#endif
