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
		final InputStream socket = new InputStream() {
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
		final TransportProtocolCommon protocol = new TransportProtocolCommon() {
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
			protected void onMessageReceived(final SshMessage msg) throws IOException {
				// TODO Auto-generated method stub

			}

			@Override
			protected void onStartTransportProtocol() throws IOException {
				// TODO Auto-generated method stub

			}

			@Override
			protected void performKeyExchange(final SshKeyExchange kex)
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
			protected void setLocalKexInit(final SshMsgKexInit msg) {
				// TODO Auto-generated method stub

			}

			@Override
			protected void setRemoteIdent(final String ident) {
				// TODO Auto-generated method stub

			}

			@Override
			protected void setRemoteKexInit(final SshMsgKexInit msg) {
				// TODO Auto-generated method stub

			}

			@Override
			protected void setupNewKeys(final byte[] encryptCSKey,
					final byte[] encryptCSIV, final byte[] encryptSCKey,
					final byte[] encryptSCIV, final byte[] macCSKey, final byte[] macSCKey)
					throws AlgorithmNotAgreedException,
					AlgorithmOperationException,
					AlgorithmNotSupportedException,
					AlgorithmInitializationException {
				// TODO Auto-generated method stub

			}

			@Override
			protected void onStop() {
				// TODO Auto-generated method stub

			}

		};
		final TransportProtocolInputStream tpis = new TransportProtocolInputStream(protocol, socket, null);

		final byte[] targetBuffer = new byte[1024];
		targetBuffer[50] = -10;
		targetBuffer[51] = -9;
		final int amountRead = tpis.readBufferedData(targetBuffer, 0, 50);
		assertEquals(50, amountRead);
		assertEquals(1, targetBuffer[0]);
		assertEquals(50, targetBuffer[49]);
		assertEquals(-10, targetBuffer[50]);
		assertEquals(-9, targetBuffer[51]);
		assertEquals(0, targetBuffer[52]);
	}
}
