package com.sshtools.j2ssh.subsystem;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.List;

import com.sshtools.j2ssh.sftp.SshFxpStatus;
import com.sshtools.j2ssh.transport.InvalidMessageException;

import junit.framework.TestCase;

public class SubsystemOutputStreamTest extends TestCase {
	public void testMessages() throws Exception {
		System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
		System.setProperty("org.apache.commons.logging.simplelog.defaultlog","DEBUG");
		
		final List<byte[]> m = new ArrayList<byte[]>();
		
		SubsystemMessageStore store = new SubsystemMessageStore() {
			@Override
			public synchronized void addMessage(byte[] msgdata)
					throws InvalidMessageException {
				m.add(msgdata);
			}
		};
		SubsystemOutputStream os = new SubsystemOutputStream(store);
		
		store.registerMessage(7, SshFxpStatus.class);
		
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		
		byte[] data = new byte[] {
				0,0,0,3,7,7,7,
				0,0,0,5,8,8,8,8,8,
				0,0,0,2,4,4
				};
		
		os.write(data, 0, 7);
		os.write(data, 7, 8);
		os.write(data, 15, 7);
		os.close();
		
		assertEquals(3, m.size());
	}
}
