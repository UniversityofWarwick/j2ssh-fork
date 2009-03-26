package com.sshtools.j2ssh.io;

import java.io.IOException;

import junit.framework.TestCase;

public class ByteArrayReaderTest extends TestCase {
	public void testInvalidLengths() throws Exception {
		ByteArrayReader reader = new ByteArrayReader(new byte[] {
			0,0,1,5, //int:261
			0,0,0,9, //int:9
			0,0,0,0,0,0,0,0 // our string
		});
		
		assertEquals(261, reader.readInt());
		try {
			reader.readString();
			fail("Should have failed");
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
	}
}
