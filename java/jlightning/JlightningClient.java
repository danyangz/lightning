package jlightning;

import java.nio.ByteBuffer;

/**
 * Lightning Client.
 *
 */
public class JlightningClient {
  static {
    System.loadLibrary("jlightning");
  }

  private long conn;

  private native long connect(String socket, String password);
  private native ByteBuffer create(long c, long id, int size);
  private native void seal(long c, long id);
  private native ByteBuffer get(long c, long id);
  private native void release(long c, long id);
  private native void delete(long c, long id); 
  private native void multiput(long c, long id, String[] fields, Object[] values);
  private native void multiupdate(long c, long id, String[] fields, Object[] values);
  private native long[] multiget(long c, long id, String[] fields);

  public native byte getbyte(long addr);
  public native void getbytes(byte[] target, long start, long addr, long size);

  public JlightningClient(String socket, String password) {
    this.conn = connect(socket, password);
  }

  public ByteBuffer create(long id, int size) {
    return create(this.conn, id, size);
  }

  public void seal(long id) {
    seal(this.conn, id);
    return;
  }

  public ByteBuffer get(long id) {
    return get(this.conn, id);
  }

  public void release(long id) {
    release(this.conn, id);
    return;
  }

  public void delete(long id) {
    delete(this.conn, id);
    return;
  }

  public void multiput(long id, String[] fields, Object[] values) {
    multiput(this.conn, id, fields, values);
    return;
  }

  public void multiupdate(long id, String[] fields, Object[] values) {
    multiupdate(this.conn, id, fields, values);
    return;
  }

  public long[] multiget(long id, String[] fields) {
    return multiget(this.conn, id, fields);
  }
}
