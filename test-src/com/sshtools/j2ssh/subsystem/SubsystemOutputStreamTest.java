package com.sshtools.j2ssh.subsystem;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import com.sshtools.j2ssh.sftp.SshFxpStatus;
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
