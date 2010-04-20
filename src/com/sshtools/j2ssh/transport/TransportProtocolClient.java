/*
 *  SSHTools - Java SSH2 API
 *
 *  Copyright (C) 2002-2003 Lee David Painter and Contributors.
 *
 *  Contributions made by:
 *
 *  Brett Smith
 *  Richard Pernavas
 *  Erwin Bolwidt
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package com.sshtools.j2ssh.transport;

import com.sshtools.j2ssh.SshException;
import com.sshtools.j2ssh.transport.cipher.SshCipher;
import com.sshtools.j2ssh.transport.cipher.SshCipherFactory;
import com.sshtools.j2ssh.transport.hmac.SshHmac;
import com.sshtools.j2ssh.transport.hmac.SshHmacFactory;
import com.sshtools.j2ssh.transport.kex.KeyExchangeException;
import com.sshtools.j2ssh.transport.kex.SshKeyExchange;
import com.sshtools.j2ssh.transport.publickey.SshKeyPair;
import com.sshtools.j2ssh.transport.publickey.SshKeyPairFactory;
import com.sshtools.j2ssh.transport.publickey.SshPublicKey;

import java.io.IOException;

import java.net.InetAddress;
import java.net.UnknownHostException;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.49 $
 */
public class TransportProtocolClient extends TransportProtocolCommon {
    /**  */
    protected SshPublicKey pk;
    private final HostKeyVerification hosts;
    private final Map services = new HashMap();
    private final SshMessageStore ms = new SshMessageStore();

    /**
     * Creates a new TransportProtocolClient object.
     *
     * @param hosts
     *
     * @throws TransportProtocolException
     */
    public TransportProtocolClient(final HostKeyVerification hosts)
        throws TransportProtocolException {
        super();
        this.hosts = hosts;
    }

    /**
     *
     *
     * @param msg
     *
     * @throws IOException
     */
    @Override
	public void onMessageReceived(final SshMessage msg) throws IOException {
        throw new IOException("No messages are registered");
    }

    /**
     *
     *
     * @throws MessageAlreadyRegisteredException
     */
    @Override
	public void registerTransportMessages()
        throws MessageAlreadyRegisteredException {
        // Setup our private message store, we wont be registering any direct messages
        ms.registerMessage(SshMsgServiceAccept.SSH_MSG_SERVICE_ACCEPT,
            SshMsgServiceAccept.class);
        this.addMessageStore(ms);
    }

    /**
     *
     *
     * @param service
     *
     * @throws IOException
     * @throws SshException
     */
    public void requestService(final Service service) throws IOException {
        // Make sure the service is supported
        if (service.getState().getValue() != ServiceState.SERVICE_UNINITIALIZED) {
            throw new IOException("The service instance must be uninitialized");
        }

        if ((state.getValue() != TransportProtocolState.CONNECTED) &&
                (state.getValue() != TransportProtocolState.PERFORMING_KEYEXCHANGE)) {
            throw new IOException("The transport protocol is not connected");
        }

        try {
            state.waitForState(TransportProtocolState.CONNECTED);
        } catch (final InterruptedException ie) {
            throw new IOException("The operation was interrupted");
        }

        service.init(Service.REQUESTING_SERVICE, this); // , null);

        // Put the service on our list awaiting acceptance
        services.put(service.getServiceName(), service);

        // Create and send the message
        SshMessage msg = new SshMsgServiceRequest(service.getServiceName());
        sendMessage(msg, this);

        try {
            // Wait for the accept message, if the service is not accepted the
            // transport protocol disconencts which should cause an excpetion
            msg = ms.popMessage(SshMsgServiceAccept.SSH_MSG_SERVICE_ACCEPT);
        } catch (final InterruptedException ex) {
            throw new SshException(
                "The thread was interrupted whilst waiting for a transport protocol message");
        }

        return;
    }

    /**
     *
     */
    @Override
	protected void onDisconnect() {
        final Iterator it = services.entrySet().iterator();
        Map.Entry entry;

        while (it.hasNext()) {
            entry = (Map.Entry) it.next();
            ((Service) entry.getValue()).stop();
        }

        services.clear();
    }

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    @Override
	protected String getDecryptionAlgorithm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedSCEncryption(),
            serverKexInit.getSupportedSCEncryption());
    }

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    @Override
	protected String getEncryptionAlgorithm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedCSEncryption(),
            serverKexInit.getSupportedCSEncryption());
    }

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    @Override
	protected String getInputStreamCompAlgortihm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedSCComp(),
            serverKexInit.getSupportedSCComp());
    }

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    @Override
	protected String getInputStreamMacAlgorithm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedSCMac(),
            serverKexInit.getSupportedSCMac());
    }

    /**
     *
     */
    @Override
	protected void setLocalIdent() {
        clientIdent = "SSH-" + PROTOCOL_VERSION + "-" +
            SOFTWARE_VERSION_COMMENTS + " [CLIENT]";
    }

    /**
     *
     *
     * @return
     */
    @Override
	public String getLocalId() {
        return clientIdent;
    }

    /**
     *
     *
     * @param msg
     */
    @Override
	protected void setLocalKexInit(final SshMsgKexInit msg) {
        log.debug(msg.toString());
        clientKexInit = msg;
    }

    /**
     *
     *
     * @return
     */
    @Override
	protected SshMsgKexInit getLocalKexInit() {
        return clientKexInit;
    }

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    @Override
	protected String getOutputStreamCompAlgorithm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedCSComp(),
            serverKexInit.getSupportedCSComp());
    }

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    @Override
	protected String getOutputStreamMacAlgorithm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedCSMac(),
            serverKexInit.getSupportedCSMac());
    }

    /**
     *
     *
     * @param ident
     */
    @Override
	protected void setRemoteIdent(final String ident) {
        serverIdent = ident;
    }

    /**
     *
     *
     * @return
     */
    @Override
	public String getRemoteId() {
        return serverIdent;
    }

    /**
     *
     *
     * @param msg
     */
    @Override
	protected void setRemoteKexInit(final SshMsgKexInit msg) {
        serverKexInit = msg;
    }

    /**
     *
     *
     * @return
     */
    @Override
	protected SshMsgKexInit getRemoteKexInit() {
        return serverKexInit;
    }

    /**
     *
     *
     * @return
     */
    public SshPublicKey getServerHostKey() {
        return pk;
    }

    /**
     *
     *
     * @throws IOException
     * @throws TransportProtocolException
     */
    @Override
	protected void onStartTransportProtocol() throws IOException {
        while ((state.getValue() != TransportProtocolState.CONNECTED) &&
                (state.getValue() != TransportProtocolState.DISCONNECTED)) {
            try {
                state.waitForStateUpdate();
            } catch (final InterruptedException ex) {
                throw new IOException("The operation was interrupted");
            }
        }

        if (state.getValue() == TransportProtocolState.DISCONNECTED) {
            if (state.hasError()) {
                throw state.getLastError();
            } else {
                throw new TransportProtocolException(
                    "The connection did not complete");
            }
        }
    }

    /**
     *
     *
     * @param kex
     *
     * @throws IOException
     */
    @Override
	protected void performKeyExchange(final SshKeyExchange kex)
        throws IOException {
        // Start the key exchange instance
        kex.performClientExchange(clientIdent, serverIdent,
            clientKexInit.toByteArray(), serverKexInit.toByteArray());

        // Verify the hoskey
        if (!verifyHostKey(kex.getHostKey(), kex.getSignature(),
                    kex.getExchangeHash())) {
            sendDisconnect(SshMsgDisconnect.HOST_KEY_NOT_VERIFIABLE,
                "The host key supplied was not valid",
                new KeyExchangeException(
                    "The host key is invalid or was not accepted!"));
        }
    }

    /**
     *
     *
     * @param encryptCSKey
     * @param encryptCSIV
     * @param encryptSCKey
     * @param encryptSCIV
     * @param macCSKey
     * @param macSCKey
     *
     * @throws AlgorithmNotAgreedException
     * @throws AlgorithmOperationException
     * @throws AlgorithmNotSupportedException
     * @throws AlgorithmInitializationException
     */
    @Override
	protected void setupNewKeys(final byte[] encryptCSKey, final byte[] encryptCSIV,
        final byte[] encryptSCKey, final byte[] encryptSCIV, final byte[] macCSKey,
        final byte[] macSCKey)
        throws AlgorithmNotAgreedException, AlgorithmOperationException,
            AlgorithmNotSupportedException, AlgorithmInitializationException {
        // Setup the encryption cipher
        SshCipher sshCipher = SshCipherFactory.newInstance(getEncryptionAlgorithm());
        sshCipher.init(SshCipher.ENCRYPT_MODE, encryptCSIV, encryptCSKey);
        algorithmsOut.setCipher(sshCipher);

        // Setup the decryption cipher
        sshCipher = SshCipherFactory.newInstance(getDecryptionAlgorithm());
        sshCipher.init(SshCipher.DECRYPT_MODE, encryptSCIV, encryptSCKey);
        algorithmsIn.setCipher(sshCipher);

        // Create and put our macs into operation
        SshHmac hmac = SshHmacFactory.newInstance(getOutputStreamMacAlgorithm());
        hmac.init(macCSKey);
        algorithmsOut.setHmac(hmac);
        hmac = SshHmacFactory.newInstance(getInputStreamMacAlgorithm());
        hmac.init(macSCKey);
        algorithmsIn.setHmac(hmac);
    }

    /**
     *
     *
     * @param key
     * @param sig
     * @param sigdata
     *
     * @return
     *
     * @throws TransportProtocolException
     */
    protected boolean verifyHostKey(final byte[] key, final byte[] sig, final byte[] sigdata)
        throws TransportProtocolException {
        // Determine the public key algorithm and obtain an instance
        final SshKeyPair pair = SshKeyPairFactory.newInstance(determineAlgorithm(
                    clientKexInit.getSupportedPublicKeys(),
                    serverKexInit.getSupportedPublicKeys()));

        // Iniialize the public key instance
        pk = pair.setPublicKey(key);

        // We have a valid key so verify it against the allowed hosts
        String host;

        try {
            final InetAddress addr = InetAddress.getByName(properties.getHost());

            if (!addr.getHostAddress().equals(properties.getHost())) {
                host = addr.getHostName() + "," + addr.getHostAddress();
            } else {
                host = addr.getHostAddress();
            }
        } catch (final UnknownHostException ex) {
            log.info("The host " + properties.getHost() +
                " could not be resolved");
            host = properties.getHost();
        }

        if (!hosts.verifyHost(host, pk)) {
            log.info("The host key was not accepted");

            return false;
        }

        final boolean result = pk.verifySignature(sig, sigdata);
        log.info("The host key signature is " +
            (result ? " valid" : "invalid"));

        return result;
    }

	@Override
	protected void onStop() {
	}
}
