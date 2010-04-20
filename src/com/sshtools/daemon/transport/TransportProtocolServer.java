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
package com.sshtools.daemon.transport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.daemon.authentication.AuthenticationProtocolServer;
import com.sshtools.daemon.configuration.ServerConfiguration;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.connection.ConnectionProtocol;
import com.sshtools.j2ssh.transport.AlgorithmInitializationException;
import com.sshtools.j2ssh.transport.AlgorithmNotAgreedException;
import com.sshtools.j2ssh.transport.AlgorithmNotSupportedException;
import com.sshtools.j2ssh.transport.AlgorithmOperationException;
import com.sshtools.j2ssh.transport.MessageAlreadyRegisteredException;
import com.sshtools.j2ssh.transport.Service;
import com.sshtools.j2ssh.transport.SshMessage;
import com.sshtools.j2ssh.transport.SshMsgDisconnect;
import com.sshtools.j2ssh.transport.SshMsgIgnore;
import com.sshtools.j2ssh.transport.SshMsgKexInit;
import com.sshtools.j2ssh.transport.SshMsgServiceRequest;
import com.sshtools.j2ssh.transport.TransportProtocolCommon;
import com.sshtools.j2ssh.transport.TransportProtocolException;
import com.sshtools.j2ssh.transport.cipher.SshCipher;
import com.sshtools.j2ssh.transport.cipher.SshCipherFactory;
import com.sshtools.j2ssh.transport.hmac.SshHmac;
import com.sshtools.j2ssh.transport.hmac.SshHmacFactory;
import com.sshtools.j2ssh.transport.kex.KeyExchangeException;
import com.sshtools.j2ssh.transport.kex.SshKeyExchange;
import com.sshtools.j2ssh.transport.publickey.SshKeyPairFactory;
import com.sshtools.j2ssh.transport.publickey.SshPrivateKey;

public class TransportProtocolServer extends TransportProtocolCommon {

    private static final int NOOP_PING_INTERVAL = 5 * 60 * 1000; // 5 minutes
	private static final Log log = LogFactory.getLog(TransportProtocolServer.class);
    private final Map acceptServices = new HashMap();
    private final ServerConfiguration config;
    private boolean refuse = false;

    private AuthenticationProtocolServer authenticationProtocol;
    private ConnectionProtocol connectionProtocol;

    private final Date createDate = new Date();

    private boolean sendIgnorePings = true;
    Timer timer = new Timer(true);

    /**
	 * Creates a new TransportProtocolServer object.
	 *
	 * @throws IOException
	 */
    public TransportProtocolServer() throws IOException {
        config = ConfigurationLoader.getConfiguration(ServerConfiguration.class);
    }

    /**
     * Constructor which stores the authentication and connection layer protocols being used
     * with this object. It will also register the authentication protocol as an accepted service,
     * so you don't need to do that. You will need to set up the authentication protocol to
     * accept the connection protocol yourself though.
     */
    public TransportProtocolServer(final AuthenticationProtocolServer auth, final ConnectionProtocol conn) throws IOException {
    	this();
        this.authenticationProtocol = auth;
        this.connectionProtocol = conn;
        acceptService(this.authenticationProtocol);
    }

    /**
 * Creates a new TransportProtocolServer object.
 *
 * @param refuse
 *
 * @throws IOException
 */
    public TransportProtocolServer(final boolean refuse) throws IOException {
        this();
        this.refuse = refuse;
    }

    @Override
    protected void onStop() {
    	timer.cancel();
    	timer.purge();
    	timer = null;
    }

    /**
 *
 */
    @Override
	protected void onDisconnect() {
        acceptServices.clear();
    }

    /**
 *
 *
 * @param service
 *
 * @throws IOException
 */
    public void acceptService(final Service service) throws IOException {
        acceptServices.put(service.getServiceName(), service);
    }

    /**
     * This will be null unless it was provided in this class's constructor.
     * It's most likely to be null when it is being configured to reject connections.
     */
    public AuthenticationProtocolServer getAuthenticationProtocolServer() {
    	return authenticationProtocol;
    }

    /**
     * This will be null unless it was provided in this class's constructor.
     * It's most likely to be null when it is being configured to reject connections.
     */
    public ConnectionProtocol getConnectionProtocol() {
    	return connectionProtocol;
    }

    /**
 *
 *
 * @throws IOException
 */
    public void refuseConnection() throws IOException {
        log.info("Refusing connection");

        // disconnect with max_connections reason.
        // (we also disconnect for other reasons, but generally only
        // when hacking attempts are being made)
        sendDisconnect(SshMsgDisconnect.TOO_MANY_CONNECTIONS,
            "Too many connections");
    }

    /**
 *
 *
 * @throws MessageAlreadyRegisteredException
 */
    @Override
	public void registerTransportMessages()
        throws MessageAlreadyRegisteredException {
        messageStore.registerMessage(SshMsgServiceRequest.SSH_MSG_SERVICE_REQUEST,
            SshMsgServiceRequest.class);
    }

    /**
 *
 *
 * @throws IOException
 */
    @Override
	protected void startBinaryPacketProtocol() throws IOException {
        if (refuse) {
            sendKeyExchangeInit();

            //sshIn.open();
            refuseConnection();
        } else {
        	if (sendIgnorePings) {
	        	timer.scheduleAtFixedRate(new TimerTask(){
					@Override
					public void run() {
						if (!sendIgnorePings) {
							this.cancel();
						} else {
							final SshMsgIgnore ping = new SshMsgIgnore();
							try {
								TransportProtocolServer.this.sendMessage(ping, TransportProtocolServer.this);
							} catch (final IOException e) {
								disconnect("IOException on ping");
							}
						}
					}
	            }, NOOP_PING_INTERVAL, NOOP_PING_INTERVAL);
        	}
            super.startBinaryPacketProtocol();
        }
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
	protected String getEncryptionAlgorithm()
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
	protected String getInputStreamCompAlgortihm()
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
	protected String getInputStreamMacAlgorithm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedCSMac(),
            serverKexInit.getSupportedCSMac());
    }

    /**
 *
 */
    @Override
	protected void setLocalIdent() {
        serverIdent = "SSH-" + PROTOCOL_VERSION + "-" +
            SOFTWARE_VERSION_COMMENTS + " [SERVER]";
    }

    /**
 *
 *
 * @return
 */
    @Override
	public String getLocalId() {
        return serverIdent;
    }

    /**
 *
 *
 * @param msg
 */
    @Override
	protected void setLocalKexInit(final SshMsgKexInit msg) {
        log.debug(msg.toString());
        serverKexInit = msg;
    }

    /**
 *
 *
 * @return
 */
    @Override
	protected SshMsgKexInit getLocalKexInit() {
        return serverKexInit;
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
	protected String getOutputStreamMacAlgorithm()
        throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedSCMac(),
            serverKexInit.getSupportedSCMac());
    }

    /**
 *
 *
 * @param ident
 */
    @Override
	protected void setRemoteIdent(final String ident) {
        clientIdent = ident;
    }

    /**
     * The client ID sent by the remote host when connecting.
     */
    @Override
	public String getRemoteId() {
        return clientIdent;
    }

    /**
 *
 *
 * @param msg
 */
    @Override
	protected void setRemoteKexInit(final SshMsgKexInit msg) {
        log.debug(msg.toString());
        clientKexInit = msg;
    }

    /**
 *
 *
 * @return
 */
    @Override
	protected SshMsgKexInit getRemoteKexInit() {
        return clientKexInit;
    }

    /**
 *
 *
 * @return
 *
 * @throws IOException
 * @throws TransportProtocolException
 */
    @Override
	protected SshMsgKexInit createLocalKexInit() throws IOException {
        final SshMsgKexInit msg = new SshMsgKexInit(properties);
        final Map keys = config.getServerHostKeys();

        if (keys.size() > 0) {
            final Iterator it = keys.entrySet().iterator();
            final List available = new ArrayList();

            while (it.hasNext()) {
                final Map.Entry entry = (Map.Entry) it.next();

                if (SshKeyPairFactory.supportsKey(entry.getKey().toString())) {
                    available.add(entry.getKey());
                } else {
                    log.warn("Server host key algorithm '" +
                        entry.getKey().toString() + "' not supported");
                }
            }

            if (available.size() > 0) {
                msg.setSupportedPK(available);
            } else {
                throw new TransportProtocolException(
                    "No server host keys available");
            }
        } else {
            throw new TransportProtocolException(
                "There are no server host keys available");
        }

        return msg;
    }

    /**
 *
 *
 * @throws IOException
 */
    @Override
	protected void onStartTransportProtocol() throws IOException {
    }

    /**
 *
 *
 * @param kex
 *
 * @throws IOException
 * @throws KeyExchangeException
 */
    @Override
	protected void performKeyExchange(final SshKeyExchange kex)
        throws IOException {
        // Determine the public key algorithm and obtain an instance
        final String keyType = determineAlgorithm(clientKexInit.getSupportedPublicKeys(),
                serverKexInit.getSupportedPublicKeys());

        // Create an instance of the public key from the factory
        //SshKeyPair pair = SshKeyPairFactory.newInstance(keyType);
        // Get the configuration and get the relevant host key
        final Map keys = config.getServerHostKeys();
        final Iterator it = keys.entrySet().iterator();
        SshPrivateKey pk; //privateKeyFile = null;

        while (it.hasNext()) {
            final Map.Entry entry = (Map.Entry) it.next();

            if (entry.getKey().equals(keyType)) {
                pk = (SshPrivateKey) entry.getValue();
                kex.performServerExchange(clientIdent, serverIdent,
                    clientKexInit.toByteArray(), serverKexInit.toByteArray(), pk);

                return;
            }
        }

        throw new KeyExchangeException(
            "No host key available for the determined public key algorithm");
    }

    /**
 *
 *
 * @param msg
 *
 * @throws IOException
 */
    @Override
	protected void onMessageReceived(final SshMessage msg) throws IOException {
        switch (msg.getMessageId()) {
	        case SshMsgServiceRequest.SSH_MSG_SERVICE_REQUEST: {
	            onMsgServiceRequest((SshMsgServiceRequest) msg);
	            break;
	        }
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
        sshCipher.init(SshCipher.ENCRYPT_MODE, encryptSCIV, encryptSCKey);
        algorithmsOut.setCipher(sshCipher);

        // Setup the decryption cipher
        sshCipher = SshCipherFactory.newInstance(getDecryptionAlgorithm());
        sshCipher.init(SshCipher.DECRYPT_MODE, encryptCSIV, encryptCSKey);
        algorithmsIn.setCipher(sshCipher);

        // Create and put our macs into operation
        SshHmac hmac = SshHmacFactory.newInstance(getOutputStreamMacAlgorithm());
        hmac.init(macSCKey);
        algorithmsOut.setHmac(hmac);
        hmac = SshHmacFactory.newInstance(getInputStreamMacAlgorithm());
        hmac.init(macCSKey);
        algorithmsIn.setHmac(hmac);
    }

    private void onMsgServiceRequest(final SshMsgServiceRequest msg)
        throws IOException {
        if (acceptServices.containsKey(msg.getServiceName())) {
            final Service service = (Service) acceptServices.get(msg.getServiceName());
            service.init(Service.ACCEPTING_SERVICE, this);
            service.start();
        } else {
            this.sendDisconnect(SshMsgDisconnect.SERVICE_NOT_AVAILABLE,
                msg.getServiceName() + " is not available");
        }
    }

    public boolean isUnderlyingConnectionAlive() {
    	try {
			return getProvider().getReadableByteChannel().isOpen();
		} catch (final IOException e) {
			log.error("Error checking if connection is alive", e);
			return false;
		}
    }

	public Date getCreatedDate() {
		return createDate;
	}

	public boolean isSendIgnorePings() {
		return sendIgnorePings;
	}

	public void setSendIgnorePings(final boolean sendIgnorePings) {
		this.sendIgnorePings = sendIgnorePings;
	}
}
