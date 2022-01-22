package jlightning;

import java.util.Arrays;
import java.nio.ByteBuffer;

public class Test {
  public static void test(JlightningClient client, int object_size) {
    byte[] b = new byte[object_size];
    Arrays.fill(b, (byte) 1);
    int len = b.length;

    System.out.print(len);
    System.out.print(",");

    int num_tests = 100;

    long start = System.nanoTime();
    for (long i = 0; i < num_tests; i++) {
      ByteBuffer buf = client.create(i, len);
      buf.put(b);
      client.seal(i);
    }

    long end = System.nanoTime();

    System.out.print((end - start)/num_tests/1e9);
    System.out.print(",");

    start = System.nanoTime();
    for (long i = 0; i < num_tests; i++) {
      ByteBuffer getbuf = client.get(i);
    }

    end = System.nanoTime();

    System.out.print((end - start)/num_tests/1e9);
    System.out.print(",");

    start = System.nanoTime();
    for (long i = 0; i < num_tests; i++) {
      client.delete(i);
    }

    end = System.nanoTime();

    System.out.print((end - start)/num_tests/1e9);
    System.out.println();
  }

  public static void main(String[] args) {
    JlightningClient client = new JlightningClient("/tmp/lightning", "password");
    for (int i = 0; i < 100; i++) {
      for (int object_size = 1024 * 1024; object_size >= 16; object_size /=2) {
        test(client, object_size);
      }
    }
  }
}
