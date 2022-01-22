#include <assert.h>
#include <iostream>
#include <jni.h>
#include <string>
#include <vector>

#include "client.h"
#include "jlightning_JlightningClient.h"

JNIEXPORT jlong JNICALL Java_jlightning_JlightningClient_connect(
    JNIEnv *env, jobject thisObj, jstring unix_socket, jstring password) {
  const char *unix_socket_s = env->GetStringUTFChars(unix_socket, nullptr);
  std::string unix_socket_string = std::string(unix_socket_s);
  const char *password_s = env->GetStringUTFChars(password, nullptr);
  std::string password_string = std::string(password_s);

  return reinterpret_cast<jlong>(
      new LightningClient(unix_socket_string, password_string));
}

JNIEXPORT jobject JNICALL Java_jlightning_JlightningClient_create(
    JNIEnv *env, jobject thisObj, jlong conn, jlong object_id, jint size) {
  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  uint8_t *value;
  client->Create(object_id, &value, size);
  return env->NewDirectByteBuffer(value, size);
}

JNIEXPORT void JNICALL Java_jlightning_JlightningClient_seal(JNIEnv *env,
                                                             jobject thisObj,
                                                             jlong conn,
                                                             jlong object_id) {
  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  client->Seal(object_id);
}

JNIEXPORT jobject JNICALL Java_jlightning_JlightningClient_get(
    JNIEnv *env, jobject thisObj, jlong conn, jlong object_id) {
  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  uint8_t *value;
  size_t size;
  client->Get(object_id, &value, &size);
  return env->NewDirectByteBuffer(value, size);
}

JNIEXPORT void JNICALL Java_jlightning_JlightningClient_release(
    JNIEnv *env, jobject thisObj, jlong conn, jlong object_id) {
  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  client->Release(object_id);
}

JNIEXPORT void JNICALL Java_jlightning_JlightningClient_delete(
    JNIEnv *env, jobject thisObj, jlong conn, jlong object_id) {
  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  client->Delete(object_id);
}

JNIEXPORT void JNICALL Java_jlightning_JlightningClient_multiput(
    JNIEnv *env, jobject thisObj, jlong conn, jlong object_id,
    jobjectArray fields, jobjectArray values) {
  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  std::vector<std::string> fields_cpp;
  for (int i = 0; i < env->GetArrayLength(fields); i++) {
    jstring field_jstring = jstring(env->GetObjectArrayElement(fields, i));
    const char *field_cpp_s = env->GetStringUTFChars(field_jstring, nullptr);
    std::string field_cpp_string = std::string(field_cpp_s);
    fields_cpp.push_back(field_cpp_string);
  }

  std::vector<int64_t> subobject_sizes;
  std::vector<uint8_t *> values_cpp;
  for (int i = 0; i < env->GetArrayLength(values); i++) {
    jbyteArray value = jbyteArray(env->GetObjectArrayElement(values, i));
    subobject_sizes.push_back(env->GetArrayLength(value));
    values_cpp.push_back((uint8_t *)env->GetPrimitiveArrayCritical(value, 0));
  }

  client->MultiPut(object_id, fields_cpp, subobject_sizes, values_cpp);
  for (int i = 0; i < env->GetArrayLength(values); i++) {
    jbyteArray value = jbyteArray(env->GetObjectArrayElement(values, i));
    env->ReleasePrimitiveArrayCritical(value, values_cpp[i], 0);
  }
}

JNIEXPORT void JNICALL Java_jlightning_JlightningClient_multiupdate(
    JNIEnv *env, jobject thisObj, jlong conn, jlong object_id,
    jobjectArray fields, jobjectArray values) {
  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  std::vector<std::string> fields_cpp;
  for (int i = 0; i < env->GetArrayLength(fields); i++) {
    jstring field_jstring = jstring(env->GetObjectArrayElement(fields, i));
    const char *field_cpp_s = env->GetStringUTFChars(field_jstring, nullptr);
    std::string field_cpp_string = std::string(field_cpp_s);
    fields_cpp.push_back(field_cpp_string);
  }

  std::vector<int64_t> subobject_sizes;
  std::vector<uint8_t *> values_cpp;
  for (int i = 0; i < env->GetArrayLength(values); i++) {
    jbyteArray value = jbyteArray(env->GetObjectArrayElement(values, i));
    subobject_sizes.push_back(env->GetArrayLength(value));
    values_cpp.push_back((uint8_t *)env->GetPrimitiveArrayCritical(value, 0));
  }

  client->MultiUpdate(object_id, fields_cpp, subobject_sizes, values_cpp);
  for (int i = 0; i < env->GetArrayLength(values); i++) {
    jbyteArray value = jbyteArray(env->GetObjectArrayElement(values, i));
    env->ReleasePrimitiveArrayCritical(value, values_cpp[i], 0);
  }
}

JNIEXPORT jlongArray JNICALL Java_jlightning_JlightningClient_multiget(
    JNIEnv *env, jobject thisObj, jlong conn, jlong object_id,
    jobjectArray fields) {

  LightningClient *client = reinterpret_cast<LightningClient *>(conn);
  std::vector<std::string> fields_cpp;
  for (int i = 0; i < env->GetArrayLength(fields); i++) {
    jstring field_jstring = jstring(env->GetObjectArrayElement(fields, i));
    const char *field_cpp_s = env->GetStringUTFChars(field_jstring, nullptr);
    std::string field_cpp_string = std::string(field_cpp_s);
    fields_cpp.push_back(field_cpp_string);
  }

  std::vector<int64_t> field_sizes;
  std::vector<uint8_t *> outfields;
  std::vector<int64_t> subobject_sizes;
  std::vector<uint8_t *> values_cpp;
  client->MultiGet(object_id, fields_cpp, &field_sizes, &outfields,
                   &subobject_sizes, &values_cpp);

  int size = field_sizes.size();
  assert(size == outfields.size());
  assert(size == subobject_sizes.size());
  assert(size == values_cpp.size());

  jlongArray ret = env->NewLongArray(size * 4);
  jlong *ptr = env->GetLongArrayElements(ret, 0);

  for (int i = 0; i < size; i++) {
    ptr[4 * i] = (jlong)field_sizes[i];
    ptr[4 * i + 1] = (jlong)outfields[i];
    ptr[4 * i + 2] = (jlong)subobject_sizes[i];
    ptr[4 * i + 3] = (jlong)values_cpp[i];
  }

  env->ReleaseLongArrayElements(ret, ptr, 0);
  return ret;
}

JNIEXPORT jbyte JNICALL Java_jlightning_JlightningClient_getbyte(
    JNIEnv *env, jobject thisObj, jlong addr) {
  return jbyte(*(char *)addr);
}

JNIEXPORT void JNICALL Java_jlightning_JlightningClient_getbytes(
    JNIEnv *env, jobject thisObj, jbyteArray target, jlong start, jlong addr,
    jlong size) {
  env->SetByteArrayRegion(target, (jsize)start, (jsize)size,
                          (const jbyte *)addr);
  return;
}
