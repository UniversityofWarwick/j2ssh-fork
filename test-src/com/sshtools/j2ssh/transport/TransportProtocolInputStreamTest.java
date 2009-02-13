package com.sshtools.j2ssh.transport;

import java.io.IOException;
import java.io.InputStream;

import com.sshtools.j2ssh.transport.kex.KeyExchangeException;
import com.sshtools.j2ssh.transport.kex.SshKeyExchange;

import junit.framework.TestCase;

public class TransportProtocolInputStreamTest extends TestCase {

	public void testNothing() {
		
	}
	public void testBasicReading() throws Exception {
		InputStream socket = new InputStream() {
			private int count;
			@Override
			public int read() throws IOException {
				count++;
				if (count == 51) {
					return -1;
				} else if (count > 51) {
					throw new IOException();
				}
				return count;
			}
		};
		TransportProtocolCommon protocol = new TransportProtocolCommon() {
			@Override
			protected String getDecryptionAlgorithm()
					throws AlgorithmNotAgreedException {
				return null;
			}

			@Override
			protected String getEncryptionAlgorithm()
					throws AlgorithmNotAgreedException {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			protected String getInputStreamCompAlgortihm()
					throws AlgorithmNotAgreedException {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			protected String getInputStreamMacAlgorithm()
					throws AlgorithmNotAgreedException {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String getLocalId() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			protected SshMsgKexInit getLocalKexInit() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			protected String getOutputStreamCompAlgorithm()
					throws AlgorithmNotAgreedException {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			protected String getOutputStreamMacAlgorithm()
					throws AlgorithmNotAgreedException {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public String getRemoteId() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			protected SshMsgKexInit getRemoteKexInit() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			protected void onDisconnect() {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void onMessageReceived(SshMessage msg) throws IOException {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void onStartTransportProtocol() throws IOException {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void performKeyExchange(SshKeyExchange kex)
					throws IOException, KeyExchangeException {
				// TODO Auto-generated method stub
				
			}

			@Override
			public void registerTransportMessages()
					throws MessageAlreadyRegisteredException {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void setLocalIdent() {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void setLocalKexInit(SshMsgKexInit msg) {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void setRemoteIdent(String ident) {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void setRemoteKexInit(SshMsgKexInit msg) {
				// TODO Auto-generated method stub
				
			}

			@Override
			protected void setupNewKeys(byte[] encryptCSKey,
					byte[] encryptCSIV, byte[] encryptSCKey,
					byte[] encryptSCIV, byte[] macCSKey, byte[] macSCKey)
					throws AlgorithmNotAgreedException,
					AlgorithmOperationException,
					AlgorithmNotSupportedException,
					AlgorithmInitializationException {
				// TODO Auto-generated method stub
				
			}
			
		};
		TransportProtocolInputStream tpis = new TransportProtocolInputStream(protocol, socket, null);
		
		byte[] targetBuffer = new byte[1024];
		targetBuffer[50] = -10;
		targetBuffer[51] = -9;
		int amountRead = tpis.readBufferedData(targetBuffer, 0, 50);
		assertEquals(50, amountRead);
		assertEquals(1, targetBuffer[0]);
		assertEquals(50, targetBuffer[49]);
		assertEquals(-10, targetBuffer[50]);
		assertEquals(-9, targetBuffer[51]);
		assertEquals(0, targetBuffer[52]);
	}
}
