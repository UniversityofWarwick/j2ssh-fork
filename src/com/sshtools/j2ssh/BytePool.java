package com.sshtools.j2ssh;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;

/**
 * Simple pool for byte arrays. The app will allocate a new byte array using
 * the get() method, and then pass it to recycle() when finished. If another
 * array of the same size is requested, it will then use one of the existing
 * arrays instead of making another one.
 * 
 * There is a minimum array size - if an array is smaller than this it won't
 * be part of the pool.
 * 
 * Beware that the byte data is not cleaned up or anything - as usual, you
 * shouldn't assume anything about the contents of a new array.
 * 
 * TODO a mechanism for ejecting arrays that haven't been reused in a while.
 */
public class BytePool {
	private static final int MAX_POOL_SIZE = 1024*1024 * 4; // 4MB
	int maxSize = MAX_POOL_SIZE;
	int minArraySize = 20;
	int size;
	
	private Collection<byte[]> availableArrays = new HashSet<byte[]>(128);
	
	public int getSize() {
		return size;
	}

	public BytePool() {
	}
	
	public BytePool(int maxPoolSize, int minArraySize) {
		this.maxSize = maxPoolSize;
		this.minArraySize = minArraySize;
	}
	
	public int getMaxSize() {
		return maxSize;
	}
	
	public synchronized byte[] get(final int requestedSize) {
		if (requestedSize < 0) {
			throw new IllegalArgumentException("requestedSize was less than 0");
		}
		if (requestedSize >= minArraySize) {
			for (Iterator<byte[]> it = availableArrays.iterator(); it.hasNext();) {
				byte[] array = it.next();
				if (array.length == requestedSize) {
					it.remove();
					this.size -= array.length;
					if (this.size < 0) {
						//we've been calculating all wrong
						throw new IllegalStateException("Recorded size less than zero");
					}
					return array;
				}
			}
		}
		return new byte[requestedSize];
	}
	
	/**
	 * Puts an array back in the place. If the pool is already too big
	 * then it won't get put in the pool - it will be discarded.
	 */
	public synchronized void recycle(byte[] arr) {
		addToPool(arr);
	}
	
	private boolean addToPool(byte[] arr) {
		if (arr.length < minArraySize || this.size + arr.length > maxSize || availableArrays.contains(arr)) {
			return false;
		}
		boolean added = availableArrays.add(arr);
		if (added) {
			this.size += arr.length;
		}
		return added;
	}
}
