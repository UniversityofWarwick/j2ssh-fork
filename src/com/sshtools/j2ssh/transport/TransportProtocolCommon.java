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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.j2ssh.SshException;
import com.sshtools.j2ssh.SshThread;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.configuration.SshConnectionProperties;
import com.sshtools.j2ssh.io.ByteArrayWriter;
import com.sshtools.j2ssh.net.TransportProvider;
import com.sshtools.j2ssh.sftp.MessageRequestId;
import com.sshtools.j2ssh.transport.kex.KeyExchangeException;
import com.sshtools.j2ssh.transport.kex.SshKeyExchange;
import com.sshtools.j2ssh.transport.kex.SshKeyExchangeFactory;
import com.sshtools.j2ssh.util.Hash;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.2 $
 */
public abstract class TransportProtocolCommon
implements TransportProtocol, Runnable
{
	// Flag to keep on running
    //private boolean keepRunning = true;

    /**  */
    protected static Log log = LogFactory.getLog(TransportProtocolCommon.class);
    private static int nextThreadNo = 1;

    /**  */
    public final static int EOL_CRLF = 1;

    /**  */
    public final static int EOL_LF = 2;

    /**  */
    public static final String PROTOCOL_VERSION = "2.0";

    /**  */
    public static String SOFTWARE_VERSION_COMMENTS = "Warwick J2SSH Fork/1.0";

    private final int threadNo = nextThreadNo++;

    /**  */
    protected BigInteger k = null;

    /**  */
    protected Boolean completeOnNewKeys = new Boolean(false);

    /**  */
    protected HostKeyVerification hosts;

    /**  */
    protected Map<String, SshKeyExchange> kexs = new HashMap<String, SshKeyExchange>();
    private boolean sendIgnore = false;

    //protected Map transportMessages = new HashMap();

    /**  */
    protected SshConnectionProperties properties;

    /**  */
    protected SshMessageStore messageStore = new SshMessageStore();

    /**  */
    protected SshMsgKexInit clientKexInit = null;

    /**  */
    protected SshMsgKexInit serverKexInit = null;

    /**  */
    protected String clientIdent = null;

    /**  */
    protected String serverIdent = null;

    /**  */
    protected TransportProtocolAlgorithmSync algorithmsIn;

    /**  */
    protected TransportProtocolAlgorithmSync algorithmsOut;

    /**  */
    protected TransportProtocolState state = new TransportProtocolState();
    private byte[] exchangeHash = null;

    /**  */
    protected byte[] sessionIdentifier = null;

    /**  */
    protected byte[] hostKey = null;

    /**  */
    protected byte[] signature = null;

    private InetAddress remoteAddress;

    /**
     * There is a bug in key re-exchange that appears when there is a lot
     * of traffic during rekeying. Until the bug is fixed, it will instead
     * delay rekeying until the connection has been quiet for this many milliseconds.
     *
     * Shouldn't be too long otherwise client IGNORE messages and other occasional
     * traffic might stop rekeying from happening.
     */
    private static final int REKEY_QUIET_WAIT_TIME = 1000;

    private final Vector<TransportProtocolEventHandler> eventHandlers = new Vector<TransportProtocolEventHandler>();

    // Storage of messages whilst in key exchange
    private final List<SshMessage> messageStack = new ArrayList<SshMessage>();

    // Message notification registry
    private final Map messageNotifications = new HashMap();

    // Key exchange lock for accessing the kex init messages
    private final Object kexLock = new Object();

    // The underlying transport provider
    private TransportProvider provider;

    // The thread object
    private SshThread thread;
    private long kexTimeout = 3600000L; // 1 hour
    //private long kexTimeout = 60000L;
    // private long kexTransferLimitKB = 100L; // 100 K
    private long kexTransferLimitKB = 1073741824L/1024L;
    // private long kexTransferLimit = 1073741824L;
    private long startTime = System.currentTimeMillis();

    private long lastMessage = startTime;

    private long transferredKB   = 0;
    private long lastTriggeredKB = 0;

    // The input stream for recieving data

    /**  */
    protected TransportProtocolInputStream sshIn;

    // The output stream for sending data

    /**  */
    protected TransportProtocolOutputStream sshOut;
    private int remoteEOL = EOL_CRLF;

    //private Map registeredMessages = new HashMap();
    private final Vector<SshMessageStore> messageStores = new Vector<SshMessageStore>();

	private long messagesReceived;

    /**
     * Creates a new TransportProtocolCommon object.
     */
    public TransportProtocolCommon() {
    }

    /**
     *
     *
     * @return
     */
    public int getConnectionId() {
        return threadNo;
    }

    /**
     *
     *
     * @return
     */
    public int getRemoteEOL() {
        return remoteEOL;
    }

    /**
     *
     *
     * @return
     */
    public TransportProtocolState getState() {
        return state;
    }

    /**
     *
     *
     * @return
     */
    public SshConnectionProperties getProperties() {
        return properties;
    }

    /**
     *
     */
    protected abstract void onDisconnect();

    /**
     *
     *
     * @param description
     */
    public void disconnect(final String description) {
        if (log.isDebugEnabled()) {
            log.debug("Disconnect: " + description);
        }

        try {
            // Send the disconnect message automatically
            sendDisconnect(SshMsgDisconnect.BY_APPLICATION, description);
            stop();
            state.setValue(TransportProtocolState.DISCONNECTED);
            state.setDisconnectReason(description);
        } catch (final Exception e) {
            log.warn("Failed to send disconnect", e);
        }
    }

    /**
     *
     *
     * @param sendIgnore
     */
    public void setSendIgnore(final boolean sendIgnore) {
        this.sendIgnore = sendIgnore;
    }

    /**
     *
     *
     * @param seconds
     *
     * @throws TransportProtocolException
     */
    public void setKexTimeout(final long seconds) throws TransportProtocolException {
        if (seconds < 60) {
            throw new TransportProtocolException(
                "Keys can only be re-exchanged every minute or more");
        }

        kexTimeout = seconds * 1000;
    }

    /**
     *
     *
     * @param kilobytes
     *
     * @throws TransportProtocolException
     */
    public void setKexTransferLimit(final long kilobytes)
        throws TransportProtocolException {
        if (kilobytes < 10) {
            throw new TransportProtocolException(
                "Keys can only be re-exchanged after every 10k of data, or more");
        }

        //kexTransferLimit = kilobytes * 1024;
        kexTransferLimitKB = kilobytes;
    }

    /*public InetSocketAddress getRemoteAddress() {
       return (InetSocketAddress)socket.getRemoteSocketAddress();
     }*/
    public long getOutgoingByteCount() {
        return sshOut.getNumBytesTransfered();
    }

    /**
     *
     *
     * @return
     */
    public long getIncomingByteCount() {
        return sshIn.getNumBytesTransfered();
    }

    /**
     *
     *
     * @param eventHandler
     */
    public void addEventHandler(final TransportProtocolEventHandler eventHandler) {
        if (eventHandler != null) {
            eventHandlers.add(eventHandler);
        }
    }

    /**
     *
     *
     * @throws MessageAlreadyRegisteredException
     */
    public abstract void registerTransportMessages()
        throws MessageAlreadyRegisteredException;

    /**
     *
     *
     * @return
     */
    public byte[] getSessionIdentifier() {
        return sessionIdentifier.clone();
    }

    /**
     *
     */
    public void run() {
      try {
        state.setValue(TransportProtocolState.NEGOTIATING_PROTOCOL);
        log.info("Registering transport protocol messages with inputstream");
        algorithmsOut = new TransportProtocolAlgorithmSync();
        algorithmsIn = new TransportProtocolAlgorithmSync();

        // Create the input/output streams
        sshIn = new TransportProtocolInputStream(
        	this,
            Channels.newInputStream(provider.getReadableByteChannel()),
            algorithmsIn);
        sshOut = new TransportProtocolOutputStream(
        	Channels.newOutputStream(provider.getWritableByteChannel()),
            this,
            algorithmsOut);

        // Register the transport layer messages that this class will handle
        messageStore.registerMessage(SshMsgDisconnect.SSH_MSG_DISCONNECT,
            SshMsgDisconnect.class);
        messageStore.registerMessage(SshMsgIgnore.SSH_MSG_IGNORE,
            SshMsgIgnore.class);
        messageStore.registerMessage(SshMsgUnimplemented.SSH_MSG_UNIMPLEMENTED,
            SshMsgUnimplemented.class);
        messageStore.registerMessage(SshMsgDebug.SSH_MSG_DEBUG,
            SshMsgDebug.class);
        messageStore.registerMessage(SshMsgKexInit.SSH_MSG_KEX_INIT,
            SshMsgKexInit.class);
        messageStore.registerMessage(SshMsgNewKeys.SSH_MSG_NEWKEYS,
            SshMsgNewKeys.class);
        registerTransportMessages();

        final List<String> supportedKexs = SshKeyExchangeFactory.getSupportedKeyExchanges();
        for (final String keyExchange : supportedKexs) {
          final SshKeyExchange kex = SshKeyExchangeFactory.newInstance(keyExchange);
          kex.init(this);
          kexs.put(keyExchange, kex);
        }

        // call abstract to initialise the local ident string
        setLocalIdent();

        // negotiate the protocol version
        negotiateVersion();
        startBinaryPacketProtocol();
      } catch (final EOFException eof) {
    	log.info("EOFException thrown - closing connection.");
      } catch (final IOException e) {
		state.setLastError(e);
		log.warn("IOException/" + e.getClass().getSimpleName() + ": " + e.getMessage());
      } catch (final Throwable e) {
        log.error("The Transport Protocol thread failed", e);
      } finally {
        thread = null;
        stop();
      }

      log.debug("The Transport Protocol has been stopped");
    }

    /**
     * Send a message to the remote host. After this method has finished
     * the message will have been fully written to the output stream and
     * flushed.
     */
    public synchronized void sendMessage(final SshMessage msg, final Object sender)
        throws IOException {
        // Send a message, if were in key exchange then add it to
        // the list unless of course it is a transport protocol or key
        // exchange message
        if (log.isDebugEnabled()) {
        	if (msg instanceof MessageRequestId) {
        		log.debug("Sending " + msg.getMessageName() + ((MessageRequestId)msg).getId());
        	} else {
        		log.debug("Sending " + msg.getMessageName());
        	}
        }

        final int currentState = state.getValue();

        if (sender instanceof SshKeyExchange ||
                sender instanceof TransportProtocolCommon ||
                (currentState == TransportProtocolState.CONNECTED)) {

            sshOut.sendMessage(msg);

            if (currentState == TransportProtocolState.CONNECTED) {
                if (sendIgnore) {
                	final SecureRandom rnd = ConfigurationLoader.getRND();
                    final byte[] length = new byte[1];
					rnd.nextBytes(length);
					final byte[] rand = new byte[(length[0] & 0xFF) + 1];
                    rnd.nextBytes(rand);
                    final SshMsgIgnore ignore = new SshMsgIgnore(new String(rand));
                    if (log.isDebugEnabled()) {
                        log.debug("Sending " + ignore.getMessageName());
                    }

                    sshOut.sendMessage(ignore);
                }
            }
        } else if (currentState == TransportProtocolState.PERFORMING_KEYEXCHANGE) {
            log.debug("Adding to message queue whilst in key exchange");

            synchronized (messageStack) {
                // Add this message to the end of the list
                messageStack.add(msg);
            }
        } else {
            throw new TransportProtocolException(
                "The transport protocol is disconnected");
        }
    }

    /**
     *
     *
     * @throws IOException
     */
    protected abstract void onStartTransportProtocol()
        throws IOException;

    /**
     *
     *
     * @param provider
     * @param properties
     *
     * @throws IOException
     */
    public void startTransportProtocol(final TransportProvider provider,
        final SshConnectionProperties properties) throws IOException {
        // Save the connected socket for later use
        this.provider = provider;
        this.properties = properties;

        if (provider.isUsingInetAddress()) {
        	if (log.isDebugEnabled()) log.debug("Saving remote address from transport provider");
        	this.remoteAddress = provider.getRemoteAddress();
        }

        // Start the transport layer message loop
        log.info("Starting transport protocol");
        thread = new SshThread(this, "Transport protocol", true);
        thread.start();
        onStartTransportProtocol();
    }

    /**
     *
     *
     * @return
     */
    public String getUnderlyingProviderDetail() {
        return provider.getProviderDetail();
    }

    /**
     *
     *
     * @param messageId
     * @param store
     *
     * @throws MessageNotRegisteredException
     */
    public void unregisterMessage(final Integer messageId, final SshMessageStore store)
        throws MessageNotRegisteredException {
        if (log.isDebugEnabled()) {
            log.debug("Unregistering message Id " + messageId.toString());
        }

        if (!messageNotifications.containsKey(messageId)) {
            throw new MessageNotRegisteredException(messageId);
        }

        final SshMessageStore actual = (SshMessageStore) messageNotifications.get(messageId);

        if (!store.equals(actual)) {
            throw new MessageNotRegisteredException(messageId, store);
        }

        messageNotifications.remove(messageId);
    }

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected abstract String getDecryptionAlgorithm()
        throws AlgorithmNotAgreedException;

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected abstract String getEncryptionAlgorithm()
        throws AlgorithmNotAgreedException;

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected abstract String getInputStreamCompAlgortihm()
        throws AlgorithmNotAgreedException;

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected abstract String getInputStreamMacAlgorithm()
        throws AlgorithmNotAgreedException;

    /**
     *
     */
    protected abstract void setLocalIdent();

    /**
     *
     *
     * @return
     */
    public abstract String getLocalId();

    /**
     *
     *
     * @param msg
     */
    protected abstract void setLocalKexInit(SshMsgKexInit msg);

    /**
     *
     *
     * @return
     */
    protected abstract SshMsgKexInit getLocalKexInit();

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected abstract String getOutputStreamCompAlgorithm()
        throws AlgorithmNotAgreedException;

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected abstract String getOutputStreamMacAlgorithm()
        throws AlgorithmNotAgreedException;

    /**
     *
     *
     * @param ident
     */
    protected abstract void setRemoteIdent(String ident);

    /**
     *
     *
     * @return
     */
    public abstract String getRemoteId();

    /**
     *
     *
     * @param msg
     */
    protected abstract void setRemoteKexInit(SshMsgKexInit msg);

    /**
     *
     *
     * @return
     */
    protected abstract SshMsgKexInit getRemoteKexInit();

    /**
     *
     *
     * @param kex
     *
     * @throws IOException
     * @throws KeyExchangeException
     */
    protected abstract void performKeyExchange(SshKeyExchange kex)
        throws IOException, KeyExchangeException;

    /**
     *
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected String getKexAlgorithm() throws AlgorithmNotAgreedException {
        return determineAlgorithm(clientKexInit.getSupportedKex(),
            serverKexInit.getSupportedKex());
    }

    public boolean isConnected() {
        return (state.getValue() == TransportProtocolState.CONNECTED) ||
        (state.getValue() == TransportProtocolState.PERFORMING_KEYEXCHANGE);
    }

    /**
     *
     *
     * @throws IOException
     * @throws KeyExchangeException
     */
    protected void beginKeyExchange() throws IOException, KeyExchangeException {
        log.info("Starting key exchange");

        //state.setValue(TransportProtocolState.PERFORMING_KEYEXCHANGE);
        String kexAlgorithm = "";

        // We now have both kex inits, this is where client/server
        // implemtations take over so call abstract methods
        try {
            // Determine the key exchange algorithm
            kexAlgorithm = getKexAlgorithm();

            if (log.isDebugEnabled()) {
                log.debug("Key exchange algorithm: " + kexAlgorithm);
            }

            // Get an instance of the key exchange algortihm
            final SshKeyExchange kex = kexs.get(kexAlgorithm);

            // Do the key exchange
            performKeyExchange(kex);

            // Record the output
            exchangeHash = kex.getExchangeHash();

            if (sessionIdentifier == null) {
                sessionIdentifier = new byte[exchangeHash.length];
                System.arraycopy(exchangeHash, 0, sessionIdentifier, 0,
                    sessionIdentifier.length);
                thread.setSessionId(sessionIdentifier);
            }

            hostKey = kex.getHostKey();
            signature = kex.getSignature();
            k = kex.getSecret();

            // Send new keys
            sendNewKeys();
            kex.reset();
        } catch (final AlgorithmNotAgreedException e) {
            sendDisconnect(SshMsgDisconnect.KEY_EXCHANGE_FAILED,
                "No suitable key exchange algorithm was agreed");
            throw new KeyExchangeException(
                "No suitable key exchange algorithm could be agreed.");
        }
    }

    /**
     *
     *
     * @return
     *
     * @throws IOException
     */
    protected SshMsgKexInit createLocalKexInit() throws IOException {
        return new SshMsgKexInit(properties);
    }

    /**
     *
     */
    protected void onCorruptMac() {
        log.fatal("Corrupt Mac on Input");

        // Send a disconnect message
        sendDisconnect(SshMsgDisconnect.MAC_ERROR, "Corrupt Mac on input",
            new SshException("Corrupt Mac on Imput"));
    }

    /**
     *
     *
     * @param msg
     *
     * @throws IOException
     */
    protected abstract void onMessageReceived(SshMessage msg)
        throws IOException;

    /**
     * Send a disconnect message with a description, and then
     * stop everything.
     */
    protected void sendDisconnect(final int reason, final String description) {
        final SshMsgDisconnect msg = new SshMsgDisconnect(reason, description, "");

        try {
            sendMessage(msg, this);
            stop();
        } catch (final Exception e) {
            log.warn("Failed to send disconnect", e);
        }
    }

    /**
     *
     *
     * @param reason
     * @param description
     * @param error
     */
    protected void sendDisconnect(final int reason, final String description,
        final IOException error) {
        state.setLastError(error);
        sendDisconnect(reason, description);
    }

    /**
     *
     *
     * @throws IOException
     */
    protected void sendKeyExchangeInit() throws IOException {
        setLocalKexInit(createLocalKexInit());
        sendMessage(getLocalKexInit(), this);
        state.setValue(TransportProtocolState.PERFORMING_KEYEXCHANGE);
    }

    /**
     *
     *
     * @throws IOException
     */
    protected void sendNewKeys() throws IOException {
        // Send new keys
        SshMsgNewKeys msg = new SshMsgNewKeys();
        sendMessage(msg, this);

        final int[] filter = new int[1];
        filter[0] = SshMsgNewKeys.SSH_MSG_NEWKEYS;
        msg = (SshMsgNewKeys) readMessage(filter);

        if (log.isDebugEnabled()) {
            log.debug("Received " + msg.getMessageName());
        }

        completeKeyExchange();
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
    protected abstract void setupNewKeys(byte[] encryptCSKey,
        byte[] encryptCSIV, byte[] encryptSCKey, byte[] encryptSCIV,
        byte[] macCSKey, byte[] macSCKey)
        throws AlgorithmNotAgreedException, AlgorithmOperationException,
            AlgorithmNotSupportedException, AlgorithmInitializationException;

    /**
     *
     *
     * @throws IOException
     * @throws TransportProtocolException
     */
    protected void completeKeyExchange() throws IOException {
        log.info("Completing key exchange");

        boolean hasReleasedLock = false;
        try {
        	algorithmsOut.lock();
        	algorithmsIn.lock();
        	
        	// Reset the state variables
            //completeOnNewKeys = new Boolean(false);
            log.debug("Making keys from key exchange output");

            // Make the keys
            final byte[] encryptionKey = makeSshKey('C');
            final byte[] encryptionIV = makeSshKey('A');
            final byte[] decryptionKey = makeSshKey('D');
            final byte[] decryptionIV = makeSshKey('B');
            final byte[] sendMac = makeSshKey('E');
            final byte[] receiveMac = makeSshKey('F');
            log.debug("Creating algorithm objects");
            setupNewKeys(encryptionKey, encryptionIV, decryptionKey,
                decryptionIV, sendMac, receiveMac);

            // Reset the key exchange
            clientKexInit = null;
            serverKexInit = null;

            algorithmsOut.release();
            algorithmsIn.release();
            hasReleasedLock = true;

            /*
             *  Update our state, we can send all packets
             *
             */
            state.setValue(TransportProtocolState.CONNECTED);

            // Send any outstanding messages
            synchronized (messageStack) {
                final Iterator it = messageStack.iterator();
                log.debug("Sending queued messages");

                while (it.hasNext()) {
                    final SshMessage msg = (SshMessage) it.next();
                    sendMessage(msg, this);
                }

                messageStack.clear();
            }
        } catch (final AlgorithmNotAgreedException anae) {
            sendDisconnect(SshMsgDisconnect.KEY_EXCHANGE_FAILED,
                "Algorithm not agreed");
            throw new TransportProtocolException(
                "The connection was disconnected because an algorithm could not be agreed");
        } catch (final AlgorithmNotSupportedException anse) {
            sendDisconnect(SshMsgDisconnect.KEY_EXCHANGE_FAILED,
                "Application error");
            throw new TransportProtocolException(
                "The connection was disconnected because an algorithm class could not be loaded");
        } catch (final AlgorithmOperationException aoe) {
            sendDisconnect(SshMsgDisconnect.KEY_EXCHANGE_FAILED,
                "Algorithm operation error");
            throw new TransportProtocolException(
                "The connection was disconnected because" +
                " of an algorithm operation error");
        } catch (final AlgorithmInitializationException aie) {
            sendDisconnect(SshMsgDisconnect.KEY_EXCHANGE_FAILED,
                "Algorithm initialization error");
            throw new TransportProtocolException(
                "The connection was disconnected because" +
                " of an algorithm initialization error");
        }
        finally {
            if( ! hasReleasedLock ) {
            	algorithmsIn.release();
                algorithmsOut.release();
            }
        }
    }

    /**
     *
     *
     * @return
     */
    protected List<TransportProtocolEventHandler> getEventHandlers() {
        return eventHandlers;
    }

    /**
     *
     *
     * @param clientAlgorithms
     * @param serverAlgorithms
     *
     * @return
     *
     * @throws AlgorithmNotAgreedException
     */
    protected String determineAlgorithm(final List clientAlgorithms,
        final List serverAlgorithms) throws AlgorithmNotAgreedException {
        if (log.isDebugEnabled()) {
            log.debug("Determine Algorithm");
            log.debug("Client Algorithms: " + clientAlgorithms.toString());
            log.debug("Server Algorithms: " + serverAlgorithms.toString());
        }

        String algorithmClient;
        String algorithmServer;
        final Iterator itClient = clientAlgorithms.iterator();

        while (itClient.hasNext()) {
            algorithmClient = (String) itClient.next();

            final Iterator itServer = serverAlgorithms.iterator();

            while (itServer.hasNext()) {
                algorithmServer = (String) itServer.next();

                if (algorithmClient.equals(algorithmServer)) {
                    log.debug("Returning " + algorithmClient);

                    return algorithmClient;
                }
            }
        }

        throw new AlgorithmNotAgreedException("Could not agree algorithm");
    }

    /**
     * @throws IOException
     */
    protected void startBinaryPacketProtocol() throws IOException {
        // Send our Kex Init
        sendKeyExchangeInit();

        SshMessage msg;

        log.debug("Rekey time limit is " + kexTimeout + "ms");

        // Perform a transport protocol message loop
        while (state.getValue() != TransportProtocolState.DISCONNECTED) {
            // Process incoming messages returning any transport protocol
            // messages to be handled here
            msg = processMessages();

            if (log.isDebugEnabled()) {
                log.debug("Received " + msg.getMessageName());
            }

            switch (msg.getMessageId()) {
            case SshMsgKexInit.SSH_MSG_KEX_INIT: {
                onMsgKexInit((SshMsgKexInit) msg);

                break;
            }

            case SshMsgDisconnect.SSH_MSG_DISCONNECT: {
                onMsgDisconnect((SshMsgDisconnect) msg);

                break;
            }

            case SshMsgIgnore.SSH_MSG_IGNORE: {
                onMsgIgnore((SshMsgIgnore) msg);

                break;
            }

            case SshMsgUnimplemented.SSH_MSG_UNIMPLEMENTED: {
                onMsgUnimplemented((SshMsgUnimplemented) msg);

                break;
            }

            case SshMsgDebug.SSH_MSG_DEBUG: {
                onMsgDebug((SshMsgDebug) msg);

                break;
            }

            default:
                onMessageReceived(msg);
            }
        }
    }

    protected abstract void onStop();

    /**
     * Stop all activity on this transport - catch and log errors where
     * possible - it's better to carry on and try to close everything
     * else than just fail and stop.
     */
    protected synchronized final void stop() {
    	if (state.getValue() == TransportProtocolState.DISCONNECTED) {
    		log.info("Skipping stop() as we are already disconnected");
    		return;
    	}

    	log.info("Disconnecting");

    	try {
    		try {
    			onDisconnect();
    		} finally {
		        for (final TransportProtocolEventHandler eventHandler : eventHandlers) {
		            eventHandler.onDisconnect(this);
		        }
    		}

	        // Close the input/output streams
	        //sshIn.close();
	        if (messageStore != null) {
	        	try {
	        		messageStore.close();
				} catch (final Exception e) {
					log.warn(e);
				}
	        }

	        // 05/01/2003 moiz change begin:
	        // all close all the registerd messageStores
	        for (final SshMessageStore ms : messageStores){
	            try {
	                ms.close();
	            } catch (final Exception e) {
	            	log.warn(e);
	            }
	        }
	        messageStores.clear();
	        // 05/01/2003 moizd change end:
	        messageStore = null;

	        try {
	        	log.info("Closing transport provider");
	            provider.close();
	        } catch (final IOException ioe) {
	        	log.warn(ioe);
	        }
    	} catch (final Exception e) {
    		//Log the exception, but carry on execution because it's more
    		//important we finish cleaning up and close the connection.
    		log.error("Error during stop()", e);
    	} finally {
        	state.setValue(TransportProtocolState.DISCONNECTED);
        	onStop();
        }
    }

    private byte[] makeSshKey(final char chr) throws IOException {
        try {
            // Create the first 20 bytes of key data
            final ByteArrayWriter keydata = new ByteArrayWriter();
            byte[] data = new byte[20];
            final Hash hash = new Hash("SHA");

            // Put the dh k value
            hash.putBigInteger(k);

            // Put in the exchange hash
            hash.putBytes(exchangeHash);

            // Put in the character
            hash.putByte((byte) chr);

            // Put the exchange hash in again
            hash.putBytes(sessionIdentifier);

            // Create the fist 20 bytes
            data = hash.doFinal();
            keydata.write(data);

            // Now do the next 20
            hash.reset();

            // Put the dh k value in again
            hash.putBigInteger(k);

            // And the exchange hash
            hash.putBytes(exchangeHash);

            // Finally the first 20 bytes of data we created
            hash.putBytes(data);
            data = hash.doFinal();

            // Put it all together
            keydata.write(data);

            // Return it
            return keydata.toByteArray();
        } catch (final NoSuchAlgorithmException nsae) {
            sendDisconnect(SshMsgDisconnect.KEY_EXCHANGE_FAILED,
                "Application error");
            throw new TransportProtocolException("SHA algorithm not supported");
        } catch (final IOException ioe) {
            sendDisconnect(SshMsgDisconnect.KEY_EXCHANGE_FAILED,
                "Application error");
            throw new TransportProtocolException("Error writing key data");
        }
    }

    private void negotiateVersion() throws IOException {
        final byte[] buf;
        final int len;
        String remoteVer = "";
        log.info("Negotiating protocol version");
        log.debug("Local identification: " + getLocalId());

        // Get the local ident string by calling the abstract method, this
        // way the implementations set the correct variables for computing the
        // exchange hash
        final String data = getLocalId() + "\r\n";

        // Send our version string
        provider.getWritableByteChannel().write(ByteBuffer.wrap(data.getBytes()));

        // Now wait for a reply and evaluate the ident string
        //buf = new byte[255];
        final StringBuffer buffer = new StringBuffer();
        char ch;
        final int MAX_BUFFER_LENGTH = 255;

        // Look for a string starting with "SSH-"
        while (!remoteVer.startsWith("SSH-") &&
                (buffer.length() < MAX_BUFFER_LENGTH)) {
            // Get the next string

        	final InputStream is = Channels.newInputStream(provider.getReadableByteChannel());

            while (((ch = (char) is.read()) != '\n') &&
                    (buffer.length() < MAX_BUFFER_LENGTH)) {
                buffer.append(ch);
            }

            // Set trimming off any EOL characters
            remoteVer = buffer.toString();

            // Guess the remote sides EOL by looking at the end of the ident string
            if (remoteVer.endsWith("\r")) {
                remoteEOL = EOL_CRLF;
            } else {
                remoteEOL = EOL_LF;
            }

            log.debug("EOL is guessed at " +
                ((remoteEOL == EOL_CRLF) ? "CR+LF" : "LF"));

            // Remove any \r
            remoteVer = remoteVer.trim();
        }

        // Get the index of the seperators
        final int l = remoteVer.indexOf("-");
        final int r = remoteVer.indexOf("-", l + 1);

        // This can happen if a server just opens a connection and sends some nonsense
        // at random. Stop them here rather than throw a confusing exception.
        if (l < 0 || r < 0) {
        	log.error("Remote machine sent unrecognised version string. Disconnecting.");
        	throw new TransportProtocolException("Unrecognised version string sent by remote server");
        }

        // Call abstract method so the implementations can set the
        // correct member variable
        setRemoteIdent(remoteVer.trim());

        if (log.isDebugEnabled()) {
            log.debug("Remote identification: " + getRemoteId());
        }

        // Get the version
        final String remoteVersion = remoteVer.substring(l + 1, r);

        // Evaluate the version, we only support 2.0
        if (!(remoteVersion.equals("2.0") || (remoteVersion.equals("1.99")))) {
            log.fatal(
                "The remote computer does not support protocol version 2.0");
            throw new TransportProtocolException(
                "The protocol version of the remote computer is not supported!");
        }

        log.info("Protocol negotiation complete");
    }

    private void onMsgDebug(final SshMsgDebug msg) {
        log.debug(msg.getMessage());
    }

    private void onMsgDisconnect(final SshMsgDisconnect msg)
        throws IOException {
        log.info("The remote computer disconnected: " + msg.getDescription());
        stop();
        state.setDisconnectReason(msg.getDescription());
    }

    private void onMsgIgnore(final SshMsgIgnore msg) {
        if (log.isDebugEnabled()) {
            log.debug("SSH_MSG_IGNORE with " +
                String.valueOf(msg.getData().length()) + " bytes of data");
        }
    }

    /**
     * A request from the remote machine to exchange fresh keys.
     *
     * See processMessages for locally initiated key exchange.
     */
    private void onMsgKexInit(final SshMsgKexInit msg) throws IOException {
        log.debug("Received remote key exchange init message");
        log.debug(msg.toString());

        synchronized (kexLock) {
            setRemoteKexInit(msg);

            // As either party can initiate a key exchange then we
            // must check to see if we have sent our own
            if (state.getValue() != TransportProtocolState.PERFORMING_KEYEXCHANGE) {
                //if (getLocalKexInit() == null) {
                sendKeyExchangeInit();
            }

            //}
            beginKeyExchange();
        }
    }

    private void onMsgNewKeys(final SshMsgNewKeys msg) throws IOException {
        // Determine whether we have completed our own
        log.debug("Received New Keys");

        synchronized (completeOnNewKeys) {
            if (completeOnNewKeys.booleanValue()) {
                completeKeyExchange();
            } else {
                completeOnNewKeys = new Boolean(true);
            }
        }
    }

    private void onMsgUnimplemented(final SshMsgUnimplemented msg) {
        if (log.isDebugEnabled()) {
            log.debug("The message with sequence no " + msg.getSequenceNo() +
                " was reported as unimplemented by the remote end.");
        }
    }

    /**
     *
     *
     * @param filter
     *
     * @return
     *
     * @throws IOException
     */
    public SshMessage readMessage(final int[] filter) throws IOException {
        byte[] msgdata = null;
        SshMessage msg;

        while (state.getValue() != TransportProtocolState.DISCONNECTED) {

            msgdata = sshIn.readMessage();

            final Integer messageId = SshMessage.getMessageId(msgdata);

            // First check the filter
            for (final int id : filter) {
                if (id == messageId.intValue()) {
                    if (messageStore.isRegisteredMessage(messageId)) {
                        final SshMessage message = messageStore.createMessage(msgdata);
                        if (log.isDebugEnabled()) {
                            log.debug("Received for transport - " + message.getMessageName());
                        }
						return message;
                    } else {
                        final SshMessageStore ms = getMessageStore(messageId);
                        msg = ms.createMessage(msgdata);
                        if (log.isDebugEnabled()) {
                            log.debug("Received " + msg.getMessageName());
                        }
                        return msg;
                    }
                }
            }

            if (messageStore.isRegisteredMessage(messageId)) {
                msg = messageStore.createMessage(msgdata);

                switch (messageId.intValue()) {
                case SshMsgDisconnect.SSH_MSG_DISCONNECT: {
                    onMsgDisconnect((SshMsgDisconnect) msg);

                    break;
                }

                case SshMsgIgnore.SSH_MSG_IGNORE: {
                    onMsgIgnore((SshMsgIgnore) msg);

                    break;
                }

                case SshMsgUnimplemented.SSH_MSG_UNIMPLEMENTED: {
                    onMsgUnimplemented((SshMsgUnimplemented) msg);

                    break;
                }

                case SshMsgDebug.SSH_MSG_DEBUG: {
                    onMsgDebug((SshMsgDebug) msg);

                    break;
                }

                default: // Exception not allowed
                    throw new IOException(
                        "Unexpected transport protocol message");
                }
            } else {
                throw new IOException("Unexpected message received");
            }
        }

        throw new IOException("The transport protocol disconnected");
    }

    /**
     * Process incoming messages
     */
    protected SshMessage processMessages() throws IOException {
        byte[] msgdata = null;
        SshMessage msg;
        SshMessageStore ms;

        while (state.getValue() != TransportProtocolState.DISCONNECTED) {
            final long currentTime = System.currentTimeMillis();

            transferredKB =  sshIn.getNumBytesTransfered()/1024
                          + sshOut.getNumBytesTransfered()/1024;

            final long kbLimit = transferredKB - lastTriggeredKB;

            if (((currentTime - startTime) > kexTimeout) ||
                (kbLimit > kexTransferLimitKB)) {
              if (currentTime > lastMessage + REKEY_QUIET_WAIT_TIME) {
	              startTime     = currentTime;
	              lastTriggeredKB = transferredKB;
	              if (log.isDebugEnabled()) {
	                log.debug("rekey");
	              }
	              sendKeyExchangeInit();
              } else {
            	  if (log.isDebugEnabled()) {
  	                log.debug("no rekey yet, waiting til less busy");
  	              }
              }
            }

            boolean hasmsg = false;

            while (!hasmsg) {
                try {
                    msgdata = sshIn.readMessage();
                    hasmsg = true;
                } catch (final InterruptedIOException ex /*SocketTimeoutException ex*/) {
                    log.info("Possible timeout on transport inputstream");
                    for (final TransportProtocolEventHandler eventHandler : eventHandlers) {
                        eventHandler.onSocketTimeout(this);
                    }
                }
            }

            this.lastMessage = currentTime;

            final Integer messageId = SshMessage.getMessageId(msgdata);

            messagesReceived++;

            if (!messageStore.isRegisteredMessage(messageId)) {
                try {
                    ms = getMessageStore(messageId);
                    msg = ms.createMessage(msgdata);

                    if (log.isDebugEnabled()) {
	                	if (msg instanceof MessageRequestId) {
	                		log.debug("Received " + msg.getMessageName() + ", ID=" + ((MessageRequestId)msg).getId().intValue());
	                	} else {
	                		log.debug("Received message " + msg.getMessageName() + "("+msg.getClass().getSimpleName()+")");
	                	}
                    }

                    ms.addMessage(msg);
                } catch (final MessageNotRegisteredException mnre) {
                    log.info("Unimplemented message received " +
                        String.valueOf(messageId.intValue()));
                    msg = new SshMsgUnimplemented(sshIn.getSequenceNo());
                    sendMessage(msg, this);
                }
            } else {
                return messageStore.createMessage(msgdata);
            }
        }

        throw new IOException("The transport protocol has disconnected");
    }

    /**
     *
     *
     * @param store
     *
     * @throws MessageAlreadyRegisteredException
     */
    public void addMessageStore(final SshMessageStore store)
        throws MessageAlreadyRegisteredException {
        messageStores.add(store);
    }

    private SshMessageStore getMessageStore(final Integer messageId) throws MessageNotRegisteredException {
        for (final SshMessageStore ms : messageStores) {
            if (ms.isRegisteredMessage(messageId)) {
                return ms;
            }
        }
        throw new MessageNotRegisteredException(messageId);
    }

    public void removeMessageStore(final SshMessageStore ms) {
        messageStores.remove(ms);
    }

	public TransportProvider getProvider() {
		return provider;
	}

	public long getMessagesReceived() {
		return messagesReceived;
	}

	/**
	 * Gets the remote address. This is only set if the connection has been
	 * started and is using the correct socket channel based transport
	 * provider. Otherwise it will be null.
	 */
	public InetAddress getRemoteAddress() {
		return remoteAddress;
	}
}
