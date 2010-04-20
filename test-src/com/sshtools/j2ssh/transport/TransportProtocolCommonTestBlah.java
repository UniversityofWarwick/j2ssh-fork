package com.sshtools.j2ssh.transport;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

import junit.framework.TestCase;

import com.sshtools.daemon.configuration.ServerConfiguration;
import com.sshtools.daemon.transport.TransportProtocolServer;
import com.sshtools.j2ssh.configuration.ConfigurationContext;
import com.sshtools.j2ssh.configuration.ConfigurationException;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.configuration.SshConnectionProperties;
import com.sshtools.j2ssh.net.TransportProvider;

public class TransportProtocolCommonTestBlah extends TestCase {

	private ServerConfiguration serverConfiguration;

	public void testLocking() throws Exception { 
		TransportProtocolCommon common = new TransportProtocolServer();

		File f = File.createTempFile("ssh", ".channel");
		f.deleteOnExit();
		final RandomAccessFile raf = new RandomAccessFile(f, "rw");
 
		SshConnectionProperties properties = new SshConnectionProperties();
//		common.startTransportProtocol(new RandomAccessFileProvider(raf),
//				properties);
//		
//		common.sendNewKeys();
	}

	protected void setUp() throws Exception {
		serverConfiguration = new ServerConfiguration(getClass()
				.getResourceAsStream("test-server.xml"));
		ConfigurationLoader.initialize(true, new TestConfigurationContext());
	}

	protected void tearDown() throws Exception {
		super.tearDown();
	}

	private final class TestConfigurationContext implements
			ConfigurationContext {
		@Override
		public boolean isConfigurationAvailable(Class cls) {
			return true;
		}

		@Override
		public void initialize() throws ConfigurationException {}

		@Override
		public Object getConfiguration(Class cls)
				throws ConfigurationException {
			if (cls == ServerConfiguration.class) {
				return serverConfiguration;
			}
			throw new ConfigurationException("No config for YOU");
		}
	}

	private static final class RandomAccessFileProvider implements
			TransportProvider {
		private final RandomAccessFile raf;

		private RandomAccessFileProvider(RandomAccessFile raf) {
			this.raf = raf;
		}

		@Override
		public boolean isUsingInetAddress() {
			return false;
		}

		@Override
		public WritableByteChannel getWritableByteChannel() throws IOException {
			return new WritableByteChannel() {
				@Override
				public int write(ByteBuffer arg0) throws IOException {
					// TODO Auto-generated method stub
					return 0;
				}

				@Override
				public void close() throws IOException {
				}

				@Override
				public boolean isOpen() {
					return true;
				}
				
			};
		}

		@Override
		public InetAddress getRemoteAddress() {
			return null;
		}

		@Override
		public ReadableByteChannel getReadableByteChannel() throws IOException {
			return new ReadableByteChannel() {
				@Override
				public boolean isOpen() {
					// TODO Auto-generated method stub
					return true;
				}
				
				@Override
				public void close() throws IOException {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public int read(ByteBuffer arg0) throws IOException {
					return 0;
				}
			};
		}

		@Override
		public String getProviderDetail() {
			return "hello";
		}

		@Override
		public void close() throws IOException {

		}
	}

}
