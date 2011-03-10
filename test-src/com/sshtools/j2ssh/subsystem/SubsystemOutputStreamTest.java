package com.sshtools.j2ssh.subsystem;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import com.sshtools.j2ssh.transport.InvalidMessageException;

public class SubsystemOutputStreamTest extends TestCase {
	
	public void setUp() {
		System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
		System.setProperty("org.apache.commons.logging.simplelog.defaultlog","DEBUG");
		
	}
	
	public void testMessages() throws Exception {
		MockMessageStore store = new MockMessageStore("testMessages");
		SubsystemOutputStream os = new SubsystemOutputStream(store);
		
		byte[] data = new byte[] {
				0,0,0,3,7,7,7,
				0,0,0,5,8,8,8,8,8,
				0,0,0,2,4,4
				};
		
		os.write(data, 0, 7);
		os.write(data, 7, 8);
		os.write(data, 15, 7);
		os.close();
		
		assertEquals(3, store.getMessages().size());
	}
	
	/**
	 * Test when a write() contains one message plus the
	 * first few bytes of the next. Only one message needs
	 * processing in each write(), though. The case for handling
	 * multiple messages in one write is covered in the next test.
	 */
	public void testMessagesWithOverlap() throws Exception {
		MockMessageStore store = new MockMessageStore("testMessages");
		SubsystemOutputStream os = new SubsystemOutputStream(store);
		
		byte[] data = new byte[] {
				0,0,0,3,7,7,7,
				0,0,0,5,8,8,8,8,8,
				0,0,0,2,4,4
				};
		
		os.write(data, 0, 7);
		os.write(data, 7, 10);
		os.write(data, 17, 5);
		os.close();
		
		assertEquals(3, store.getMessages().size());
	}
	
	/**
	 * If incoming data contains the end of one message and the start
	 * of another, we will simply advance a marker to the start of the new
	 * message rather than copy bytes and reset the buffer. This is fine
	 * every now and again but if a client repeatedly does it eventually the
	 * buffer will become oversized.
	 * 
	 * Fix is to force a buffer reset after some threshold (copying the trailing
	 * data to the start)
	 */
	public void testConstantlyOverlappingMessages() throws Exception {
		MockMessageStore store = new MockMessageStore("testMessages");
		SubsystemOutputStream os = new SubsystemOutputStream(store);
		
		// Build a message
		ByteArrayOutputStream bas = new ByteArrayOutputStream();
		int length = 1024*8;
		bas.write(toByteArray(length));
		for (int i=0; i<length; i++) {
			bas.write(5); // any byte data, value isn't important.
		}
		byte[] message1 = bas.toByteArray();
		
		// Build an array with the end of the message rotated to the front,
		// so we can repeatedly pass this to the output stream
		ByteArrayOutputStream joined = new ByteArrayOutputStream();
		joined.write(message1, 1024, message1.length-1024);
		joined.write(message1, 0, 1024);
		byte[] joinedArray = joined.toByteArray();
		
		// Send the first part of a message before joinedArray, else it will be garbage
		os.write(message1, 0, 1024);
		for (int i=0; i<1000; i++) {
			os.write(joinedArray);
		}
		os.write(message1, 1024, message1.length-1024);
		
		assertEquals(1001, store.getMessages().size());
		assertEquals(length, store.getMessages().get(0).length);
	}
	
	private byte[] toByteArray(int value) {
		return new byte[]{
			(byte)(value >>> 24),
            (byte)(value >>> 16),
            (byte)(value >>> 8),
            (byte)value
		};
	}
	
	/**
	 * Testing what happens if a call to write() contains the bytes
	 * for the end of two messages. In the original implementation,
	 * processMessages() gets called once for this, and it will
	 * only process a single message. Its behaviour relies on
	 * write() being called again to push the second message through,
	 * but at the end of a file transfer the OpenSSH client will wait
	 * for a response to the last read/write message, and will hang forever.
	 * 
	 * This tests that both messages are processed in one
	 * call to processMessages.
	 */
	public void testMultipleMessagesInOneWrite() throws Exception {
		MockMessageStore store = new MockMessageStore("testMessages");
		SubsystemOutputStream os = new SubsystemOutputStream(store);
		
		byte[] data = new byte[] {
				0,0,0,3,7,7,7,
				0,0,0,5,8,8,8,8,8,
				0,0,0,2,4,4
				};
		
		os.write(data, 0, 7);
		//Two messages are written here.
		os.write(data, 7, 15);
		
		assertEquals(3, store.getMessages().size());
		
		//if we re-write the same buffer, it adds three messages
		//each time.
		os.write(data);
		assertEquals(6, store.getMessages().size());
		os.write(data);
		assertEquals(9, store.getMessages().size());
	}
	
	class MockMessageStore extends SubsystemMessageStore {
		private final List<byte[]> m = new ArrayList<byte[]>();
		
		public MockMessageStore(String name) {
			super(name);
		}
		
		@Override
		public synchronized void addMessage(byte[] msgdata)
				throws InvalidMessageException {
			m.add(msgdata);
		}
		
		public List<byte[]> getMessages() {
			return m;
		}
	}
}
