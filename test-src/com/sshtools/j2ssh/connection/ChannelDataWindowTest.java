package com.sshtools.j2ssh.connection;

import junit.framework.TestCase;

public class ChannelDataWindowTest extends TestCase {
	public void testBlocking() throws Exception {
		final ChannelDataWindow window = new ChannelDataWindow("charles");
		
		window.increaseWindowSpace(10);
		
		Thread decreaser = new Thread() {
			public void run() {
				window.consumeWindowSpace(50);
			}
		};
		
		Thread increaser = new Thread() {
			public void run() {
				window.increaseWindowSpace(100);
			}
		};
		
		assertEquals(10, window.getWindowSpace());
		
		decreaser.start();
		
		assertEquals(10, window.getWindowSpace());
		
		increaser.start();
		increaser.join();
		
		decreaser.join();
		
		assertEquals(60, window.getWindowSpace());
	}
}
