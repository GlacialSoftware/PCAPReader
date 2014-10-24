/***************************************************************************
 * Copyright (C) 2007, Sly Technologies, Inc                               *
 * Distributed under the Lesser GNU Public License  (LGPL)                 *
 ***************************************************************************/

/*
 * Utility file that provides various conversion methods for chaging objects
 * back and forth between C and Java JNI.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <jni.h>

#ifndef WIN32
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#endif /*WIN32*/

#include "jnetpcap_dumper.h"
#include "jnetpcap_utils.h"
#include "nio_jmemory.h"

jclass pcapDumperClass = 0;

jmethodID pcapDumperConstructorMID = 0;

jfieldID pcapDumperPhysicalFID = 0;

/*
 * Function: new PcapDumper()
 * Description: allocates a new object and assigns to C peer structure
 * Return: new PcapDumper object, local reference
 */
jobject newPcapDumper(JNIEnv *env, pcap_dumper_t *dumper) {

	jobject obj = env->NewObject(pcapDumperClass, pcapDumperConstructorMID);
	if (obj == NULL) {
		return NULL; // Out of memory, exception already thrown
	}
	

	setPcapDumper(env, obj, dumper);

	return obj;
}

/*
 * Function: getPcapDumper
 * Description: retrieves the peering structure by looking up its address within
 *              the java object.
 * Return: ptr to the structure or null on exception
 */
pcap_dumper_t *getPcapDumper(JNIEnv *env, jobject obj) {

	jlong physical = env->GetLongField(obj, pcapDumperPhysicalFID);

	return (pcap_dumper_t *)toPtr(physical);
}

/*
 * Function: setPcapDumper
 * Description: store the peering structure point within the PcapDumper object.
 *              Can be later retrieved using getPcapDumper function.
 */
void setPcapDumper(JNIEnv *env, jobject obj, pcap_dumper_t *dumper) {
	jlong physical = toLong(dumper);

	env->SetLongField(obj, pcapDumperPhysicalFID, physical);
}

/*
 * Class:     org_jnetpcap_PcapDumper
 * Method:    initIDs
 * Signature: ()V
 */
EXTERN void JNICALL Java_org_jnetpcap_PcapDumper_initIDs
(JNIEnv *env, jclass jclazz) {

	pcapDumperClass = (jclass) env->NewGlobalRef(jclazz); // This one is easy

	if ( (pcapDumperConstructorMID = env->GetMethodID(jclazz, "<init>", "()V"))
			== NULL) {
		throwException(env, NO_SUCH_METHOD_EXCEPTION,
				"Unable to initialize constructor PcapDumper.PcapDumper()");
		return;
	}

	if ( (pcapDumperPhysicalFID = env->GetFieldID(jclazz, "physical", "J")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field PcapDumper.physical:long");
		return;
	}

}

/*
 * Class:     org_jnetpcap_PcapDumper
 * Method:    dump
 * Signature: (Lorg/jnetpcap/PcapHeader;Ljava/nio/ByteBuffer;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapDumper_dump__Lorg_jnetpcap_PcapHeader_2Ljava_nio_ByteBuffer_2
  (JNIEnv *env, jobject obj, jobject jpcapheader, jobject jbytebuffer) {
	
	if (jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "buffer argument null");
		return;
	}

	pcap_dumper_t *d = getPcapDumper(env, obj);
	if (d == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "dumper argument null");
		return; // Exception already thrown
	}
	
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, jpcapheader);
	if (hdr == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "header argument null");
		return;
	}


	const u_char *b = (u_char *)env->GetDirectBufferAddress(jbytebuffer);
	if (b == NULL) {
		throwException(env, NULL_PTR_EXCEPTION,
				"Unable to retrieve native address from ByteBuffer object");
		return;
	}

	pcap_dump((u_char *)d, hdr, b);
}

/*
 * Class:     org_jnetpcap_PcapDumper
 * Method:    dump
 * Signature: (Lorg/jnetpcap/PcapHeader;Lorg/jnetpcap/nio/JBuffer;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_PcapDumper_dump__Lorg_jnetpcap_PcapHeader_2Lorg_jnetpcap_nio_JBuffer_2
  (JNIEnv *env, jobject obj, jobject jpcapheader, jobject jbuffer) {
	
	if (jbuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "buffer argument null");
		return;
	}

	pcap_dumper_t *d = getPcapDumper(env, obj);
	if (d == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "dumper argument null");
		return; // Exception already thrown
	}
	
	pcap_pkthdr *hdr = (pcap_pkthdr *)getJMemoryPhysical(env, jpcapheader);
	if (hdr == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "header argument null");
		return;
	}

	const u_char *b = (u_char *)getJMemoryPhysical(env, jbuffer);
	if (hdr == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "header argument null");
		return;
	}

	pcap_dump((u_char *)d, hdr, b);
}


/*
 * Class:     org_jnetpcap_PcapDumper
 * Method:    dump
 * Signature: (JIIILjava/nio/ByteBuffer;)V
 */
EXTERN void JNICALL Java_org_jnetpcap_PcapDumper_dump__JIIILjava_nio_ByteBuffer_2
(JNIEnv *env, jobject obj, jlong jsec, jint jusec, jint jcap, jint jlen, jobject jbytebuffer) {

	if (jbytebuffer == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "buffer argument null");
		return;
	}

	pcap_dumper_t *d = getPcapDumper(env, obj);
	if (d == NULL) {
		return; // Exception already thrown
	}

	pcap_pkthdr hdr;
	hdr.ts.tv_sec = (int)jsec;
	hdr.ts.tv_usec = (int) jusec;
	hdr.caplen = (int)jcap;
	hdr.len = (int) jlen;
	const u_char *b = (u_char *)env->GetDirectBufferAddress(jbytebuffer);
	if (b == NULL) {
		throwException(env, NULL_PTR_EXCEPTION,
				"Unable to retrieve native address from ByteBuffer object");
		return;
	}

	pcap_dump((u_char *)d, &hdr, b);
}

/*
 * Class:     org_jnetpcap_PcapDumper
 * Method:    ftell
 * Signature: ()J
 */
EXTERN jlong JNICALL Java_org_jnetpcap_PcapDumper_ftell
(JNIEnv *env, jobject obj) {

#ifdef WIN32
	pcap_dumper_t *d = getPcapDumper(env, obj);
	if (d == NULL) {
		return -1; // Exception already thrown
	}

	return (jlong) pcap_dump_ftell(d);
#else
	throwException(env, UNSUPPORTED_OPERATION_EXCEPTION, NULL);
	return -1;
#endif
}

/*
 * Class:     org_jnetpcap_PcapDumper
 * Method:    flush
 * Signature: ()I
 */
EXTERN jint JNICALL Java_org_jnetpcap_PcapDumper_flush
(JNIEnv *env, jobject obj) {

	pcap_dumper_t *d = getPcapDumper(env, obj);
	if (d == NULL) {
		return -1; // Exception already thrown
	}

	return (jint) pcap_dump_flush(d);
}

/*
 * Class:     org_jnetpcap_PcapDumper
 * Method:    close
 * Signature: ()V
 */
EXTERN void JNICALL Java_org_jnetpcap_PcapDumper_close
(JNIEnv *env, jobject obj) {

	pcap_dumper_t *d = getPcapDumper(env, obj);
	if (d == NULL) {
		return; // Exception already thrown
	}

	pcap_dump_close(d);

	setPcapDumper(env, obj, NULL);
}

