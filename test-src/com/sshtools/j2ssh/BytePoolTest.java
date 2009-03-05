package com.sshtools.j2ssh;

import junit.framework.TestCase;

public class BytePoolTest extends TestCase {
	
	private BytePool pool;
	
	public void setUp() {
		pool = new BytePool(3000, 200);
	}
	
	public void testTwoSeparateArrays() {
		byte[] arr1 = pool.get(1000);
		byte[] arr2 = pool.get(1000);
		byte[] arr3 = pool.get(500);
		
		// pool is still empty because no arrays are stored as available.
		assertEquals(0, pool.getSize());
		
		assertEquals(1000, arr1.length);
		assertEquals(1000, arr2.length);
		assertEquals(500,  arr3.length);
		
		assertNotSame(arr1, arr2);
		assertNotSame(arr1, arr3);
	}
	
	/**
	 *  Test that if the first array is sent for recycling,
	 *  the pool can then re-use it for another same-size request.
	 */
	public void testRecyclingArrays() {
		byte[] arr1 = pool.get(1000);
		
		assertEquals(0, pool.getSize());
		
		pool.recycle(arr1);
		
		assertEquals(1000, pool.getSize());
		
		byte[] arr3 = pool.get(500);
		byte[] arr2 = pool.get(1000);
		
		assertEquals(0, pool.getSize());
		
		assertSame(arr1, arr2);
		assertNotSame(arr1, arr3);
	}
	
	public void testMaxSize() {
		byte[] arr1 = pool.get(1000);
		byte[] arr2 = pool.get(1500);
		byte[] arr3 = pool.get(900);
		
		assertEquals(0, pool.getSize());
		
		pool.recycle(arr1);
		assertEquals(1000, pool.getSize());
		
		pool.recycle(arr2);
		assertEquals(2500, pool.getSize());
		
		// Recycling this one won't insert the array, because it would make
		// the pool too big. It is simply discarded.
		pool.recycle(arr3);
		assertEquals(2500, pool.getSize());
		
		// Check that getting a 900 size array returns a different array
		byte[] arr4 = pool.get(900);
		assertNotSame(arr3,arr4);
		
		// But we can re-use the other two arrays.
		assertSame(arr1,pool.get(1000));
		assertSame(arr2,pool.get(1500));
	}
	
	/**
	 * Check that arrays smaller than the specified minimum size, do
	 * not enter the pool.
	 */
	public void testMinArraySize() {
		byte[] small = pool.get(50);
		pool.recycle(small);
		byte[] anotherSmall = pool.get(50);
		assertNotSame(small, anotherSmall);
	}
	
	public void testDoubleRecycle() {
		byte[] peter = pool.get(500);
		
		assertEquals(0, pool.getSize());
		pool.recycle(peter);
		assertEquals(500, pool.getSize());
		pool.recycle(peter);
		assertEquals(500, pool.getSize());
	}
	
	/**
	 * Assert that the equals() method for an array doesn't check members,
	 * it just checks it's the same object. We don't want an expensive
	 * member check, we really do just want to check they're the same
	 * object.
	 */
	public void testArrayEqualsBehaviour() {
		int[] a = new int[]{1,2,3,4,5};
		int[] aa = a;
		int[] b = new int[]{1,2,3,4,5};
		assertFalse(a.equals(b));
		assertTrue(a.equals(aa));
		
	}
}
