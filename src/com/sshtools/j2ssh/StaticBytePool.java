package com.sshtools.j2ssh;

/**
 * Madcap way of reusing same-sized byte arrays after they have
 * been used, to try and reduce memory churn.
 */
public class StaticBytePool {
	private static BytePool pool = new BytePool();
	
	public static byte[] get(int size) {
		return pool.get(size);
	}
	
	public static void recycle(byte[] arr) {
		pool.recycle(arr);
	}
}
