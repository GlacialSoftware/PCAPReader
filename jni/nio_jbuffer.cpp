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

#include "nio_jbuffer.h"
#include "nio_jmemory.h"
#include "jnetpcap_utils.h"
#include "org_jnetpcap_nio_JBuffer.h"
#include "export.h"

/****************************************************************
 * **************************************************************
 * 
 * NON Java declared native functions. Private scan function
 * 
 * **************************************************************
 ****************************************************************/


/****************************************************************
 * **************************************************************
 * 
 * Java declared native functions
 * 
 * **************************************************************
 ****************************************************************/
jfieldID jbufferOrderFID = 0;
jfieldID jbufferReadonlyFID = 0;

#define ITOA_BUF 16

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    initIds
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_initIds
(JNIEnv *env, jclass clazz) {

	jclass c = clazz;
	
	if ( ( jbufferOrderFID = env->GetFieldID(c, "order", "Z")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JBuffer.order:boolean");
		return;
	}

	if ( ( jbufferReadonlyFID = env->GetFieldID(c, "readonly", "Z")) == NULL) {
		throwException(env, NO_SUCH_FIELD_EXCEPTION,
				"Unable to initialize field JBuffer.readonly:boolean");
		return;
	}
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByte0
 * Signature: (JI)B
 */
JNIEXPORT jbyte JNICALL Java_org_jnetpcap_nio_JBuffer_getByte0
  (JNIEnv *env, jclass clazz, jlong address, jint index) {
	return *((jbyte *)toPtr(address + index));
}


/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getByteArray0
 * Signature: (JI[BIII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_jnetpcap_nio_JBuffer_getByteArray0
  (JNIEnv *env, jclass clazz, jlong address, jint index, jbyteArray jarray,
		  jint jarraySize, jint offset, jint length) {
	
	jbyte *mem = (jbyte *)toPtr(address + index);
	
	env->SetByteArrayRegion(jarray, offset, length, mem);
	
	return jarray;
}


/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getDouble0
 * Signature: (JZI)D
 */
JNIEXPORT jdouble JNICALL Java_org_jnetpcap_nio_JBuffer_getDouble0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index) {
	
	u_int64_t *mem = (u_int64_t *)toPtr(address + index);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	 u_int64_t data = *(mem);
	 
	/*
	 * We can't just typecast u_int64 to a double. The double has to be read
	 * out of memory using a double pointer.
	 */
	data = ENDIAN64_GET(big, data);
	return *((jdouble *)&data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getFloat0
 * Signature: (JZI)F
 */
JNIEXPORT jfloat JNICALL Java_org_jnetpcap_nio_JBuffer_getFloat0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index) {
	
	u_int32_t *mem = (u_int32_t *)toPtr(address + index);
	
	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int32_t data = *(mem);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	data = ENDIAN32_GET(big, data);
	return *((jfloat *)&data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getInt0
 * Signature: (JZI)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getInt0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index) {
	
	jint *mem = (jint *)toPtr(address + index);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register jint data = *(mem);
	
	return ENDIAN32_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getLong0
 * Signature: (JZI)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JBuffer_getLong0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index) {
	
	u_int64_t *mem = (u_int64_t *)toPtr(address + index);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int64_t data = *(mem);
	
	return ENDIAN64_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getShort0
 * Signature: (JZI)S
 */
JNIEXPORT jshort JNICALL Java_org_jnetpcap_nio_JBuffer_getShort0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index) {
	
	jshort *mem = (jshort *)toPtr(address + index);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register jshort data = *(mem);
	
	return ENDIAN16_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUByte0
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getUByte0
(JNIEnv *env, jclass clazz, jlong address, jint index) {
	
	jbyte *mem = (jbyte *)toPtr(address + index);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int8_t data = (u_int8_t)*(mem);
	
	return (jint) data;

}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUInt0
 * Signature: (JZI)J
 */
JNIEXPORT jlong JNICALL Java_org_jnetpcap_nio_JBuffer_getUInt0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index) {
	
	u_int32_t *mem = (u_int32_t *)toPtr(address + index);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int32_t data = *(mem);
	
	return (jlong) ENDIAN32_GET(big, data);

}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    getUShort0
 * Signature: (JZI)I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JBuffer_getUShort0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index) {
	
	u_int16_t *mem = (u_int16_t *)toPtr(address + index);

	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	register u_int16_t data = *(mem);
	
	return (jint) ENDIAN16_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setByte0
 * Signature: (JIB)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setByte0
(JNIEnv *env, jclass clazz, jlong address, jint index, jbyte jval) {
	
	jbyte *mem = (jbyte *)toPtr(address + index);
	
	*(mem) = jval;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setByteArray0
 * Signature: (JI[BI)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setByteArray0
  (JNIEnv *env, jclass clazz, jlong address, jint index, jbyteArray jarray, jint jarraySize) {
	
	jbyte *mem = (jbyte *)toPtr(address + index);
	
	env->GetByteArrayRegion(jarray, 0, jarraySize, (mem));
	
	return;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setDouble0
 * Signature: (JZID)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setDouble0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index, jdouble jval) {
	
	u_int64_t *mem = (u_int64_t *)toPtr(address + index);
	
	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int64_t data = *(u_int64_t *)(&jval);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	*(mem) = ENDIAN64_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setFloat0
 * Signature: (JZIF)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setFloat0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index, jfloat jval) {
	
	u_int32_t *mem = (u_int32_t *)toPtr(address + index);
	
	/*
	 * For efficiency of the endian byte swapping, convert to an atom and use
	 * a CPU register if possible during conversion.
	 */
	u_int32_t data = *(u_int32_t *)(&jval);

	/*
	 * We can't just typecast u_int32 to a float. The float has to be read
	 * out of memory using a float pointer.
	 */
	*(mem) = ENDIAN32_GET(big, data);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setInt0
 * Signature: (JZII)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setInt0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index, jint jval) {
	
	u_int32_t *mem = (u_int32_t *)toPtr(address + index);
	
	*(mem) = ENDIAN32_GET(big, jval);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setLong0
 * Signature: (JZIJ)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setLong0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index, jlong jval) {
	
	u_int64_t *mem = (u_int64_t *)toPtr(address + index);
	
	*(mem) = ENDIAN64_GET(big, jval);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setShort0
 * Signature: (JZIS)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setShort0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index, jshort jval) {
	
	u_int16_t *mem = (u_int16_t *)toPtr(address + index);
	
	*(mem) = ENDIAN16_GET(big, jval);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUByte0
 * Signature: (JII)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUByte0
(JNIEnv *env, jclass clazz, jlong address, jint index, jint jval) {
	
	jbyte *mem = (jbyte *)toPtr(address + index);
	
	*(mem) = (jbyte) jval;
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUInt0
 * Signature: (JZIJ)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUInt0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index, jlong jval) {
	
	u_int32_t *mem = (u_int32_t *)toPtr(address + index);
	
	register jint temp = (jint) jval;
	
	*(mem) = ENDIAN32_GET(big, temp);
}

/*
 * Class:     org_jnetpcap_nio_JBuffer
 * Method:    setUShort0
 * Signature: (JZII)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_nio_JBuffer_setUShort0
(JNIEnv *env, jclass clazz, jlong address, jboolean big, jint index, jint jval) {
	
	u_int16_t *mem = (u_int16_t *)toPtr(address + index);
	
	register jshort temp = (jshort) jval;
	
	*(mem) = ENDIAN16_GET(big, temp);
}


/*
 * Class:     org_jnetpcap_nio_JObjectBuffer
 * Method:    getObject
 * Signature: (Ljava/lang/Class;I)Ljava/lang/Object;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_nio_JObjectBuffer_getObject
  (JNIEnv *env, jobject obj, jclass clazz, jint offset) {
	
	
	jbyte *mem = (jbyte *)getJMemoryPhysical(env, obj);
	if (mem == NULL) {
		throwException(env, NULL_PTR_EXCEPTION, "JBuffer not initialized");
		return NULL;
	}
//#define DEBUG
#ifdef DEBUG
	printf("getObject(): here mem=%p offset=%d *=%p\n", 
			mem, 
			offset, 
			*((jobject *) (mem + offset)));
	fflush(stdout);
#endif
	return *((jobject *) (mem + offset));
}

/*
 * Class:     org_jnetpcap_nio_JObjectBuffer
 * Method:    sizeofJObject
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_nio_JObjectBuffer_sizeofJObject
  (JNIEnv *env, jclass clazz) {
	
	return sizeof(jobject);
}

