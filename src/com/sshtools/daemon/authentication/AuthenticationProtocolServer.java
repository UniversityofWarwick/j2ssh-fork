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
package com.sshtools.daemon.authentication;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.daemon.configuration.ServerConfiguration;
import com.sshtools.daemon.platform.NativeAuthenticationProvider;
import com.sshtools.daemon.util.StringUtil;
import com.sshtools.j2ssh.SshException;
import com.sshtools.j2ssh.SshThread;
import com.sshtools.j2ssh.authentication.AuthenticationProtocolException;
import com.sshtools.j2ssh.authentication.AuthenticationProtocolListener;
import com.sshtools.j2ssh.authentication.AuthenticationProtocolState;
import com.sshtools.j2ssh.authentication.SshMsgUserAuthBanner;
import com.sshtools.j2ssh.authentication.SshMsgUserAuthFailure;
import com.sshtools.j2ssh.authentication.SshMsgUserAuthRequest;
import com.sshtools.j2ssh.authentication.SshMsgUserAuthSuccess;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.connection.ConnectionProtocol;
import com.sshtools.j2ssh.io.ByteArrayReader;
import com.sshtools.j2ssh.transport.AsyncService;
import com.sshtools.j2ssh.transport.Service;
import com.sshtools.j2ssh.transport.SshMessage;
import com.sshtools.j2ssh.transport.SshMessageStore;
import com.sshtools.j2ssh.transport.TransportProtocolState;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.11 $
 */
public class AuthenticationProtocolServer extends AsyncService {

    public static final String SERVICE_NAME = "ssh-userauth";
	private static final Log log = LogFactory.getLog(AuthenticationProtocolServer.class);

    private final List completedAuthentications = new ArrayList();
    private final Map acceptServices = new HashMap();
    private List<String> availableAuths;
    private String serviceToStart;
    private final int[] messageFilter = new int[1];
    private final SshMessageStore methodMessages = new SshMessageStore();
    private int attempts = 0;
    private boolean completed = false;

    private final List<AuthenticationProtocolListener> listeners = new ArrayList<AuthenticationProtocolListener>();

    /**
 * Creates a new AuthenticationProtocolServer object.
 */
    public AuthenticationProtocolServer() {
        super(SERVICE_NAME);
        messageFilter[0] = SshMsgUserAuthRequest.SSH_MSG_USERAUTH_REQUEST;
    }


    public void addListener(final AuthenticationProtocolListener listener) {
    	listeners.add(listener);
    }


    /**
 *
 *
 * @throws java.io.IOException
 */
    @Override
	protected void onServiceAccept() throws java.io.IOException {
    }

    /**
 *
 *
 * @param startMode
 *
 * @throws java.io.IOException
 */
    @Override
	protected void onServiceInit(final int startMode) throws java.io.IOException {
        // Register the required messages
        messageStore.registerMessage(SshMsgUserAuthRequest.SSH_MSG_USERAUTH_REQUEST,
            SshMsgUserAuthRequest.class);
        transport.addMessageStore(methodMessages);
    }

    /**
 *
 *
 * @return
 */
    public byte[] getSessionIdentifier() {
        return transport.getSessionIdentifier();
    }

    /**
 *
 *
 * @return
 */
    public TransportProtocolState getConnectionState() {
        return transport.getState();
    }

    /**
 *
 *
 * @param msg
 *
 * @throws IOException
 */
    public void sendMessage(final SshMessage msg) throws IOException {
        transport.sendMessage(msg, this);
    }

    /**
 *
 *
 * @return
 *
 * @throws IOException
 * @throws SshException
 */
    public SshMessage readMessage() throws IOException {
        try {
            return methodMessages.nextMessage();
        } catch (final InterruptedException ex) {
            throw new SshException("The thread was interrupted");
        }
    }

    /**
 *
 *
 * @param messageId
 * @param cls
 */
    public void registerMessage(final int messageId, final Class cls) {
        methodMessages.registerMessage(messageId, cls);
    }

    /**
 *
 *
 * @throws java.io.IOException
 * @throws AuthenticationProtocolException
 */
    @Override
	protected void onServiceRequest() throws java.io.IOException {
        // Send a user auth banner if configured
        final ServerConfiguration server = ConfigurationLoader.getConfiguration(ServerConfiguration.class);

        if (server == null) {
            throw new AuthenticationProtocolException(
                "Server configuration unavailable");
        }

        final List<String> allowed = server.getAllowedAuthentications();
        availableAuths = new ArrayList<String>();
        for (final String method : SshAuthenticationServerFactory.getSupportedMethods()) {
            if (allowed.contains(method)) {
                availableAuths.add(method);
            }
        }

        if (availableAuths.size() <= 0) {
            throw new AuthenticationProtocolException(
                "No valid authentication methods have been specified");
        }

        // Accept the service request
        sendServiceAccept();

        final String bannerFile = server.getAuthenticationBanner();

        if (bannerFile != null) {
            if (bannerFile.length() > 0) {
                final InputStream in = ConfigurationLoader.loadFile(bannerFile);

                if (in != null) {
                    final byte[] data = new byte[in.available()];
                    in.read(data);
                    in.close();

                    final SshMsgUserAuthBanner bannerMsg = new SshMsgUserAuthBanner(new String(data, ByteArrayReader.UTF_8));
                    transport.sendMessage(bannerMsg, this);
                } else {
                    log.info("The banner file '" + bannerFile +
                        "' was not found");
                }
            }
        }
    }

    /**
 *
 *
 * @param msg
 *
 * @throws java.io.IOException
 * @throws AuthenticationProtocolException
 */
    @Override
	protected void onMessageReceived(final SshMessage msg) throws java.io.IOException {
        switch (msg.getMessageId()) {
        case SshMsgUserAuthRequest.SSH_MSG_USERAUTH_REQUEST: {
            onMsgUserAuthRequest((SshMsgUserAuthRequest) msg);

            break;
        }

        default:
            throw new AuthenticationProtocolException(
                "Unregistered message received!");
        }
    }

    /**
 *
 *
 * @return
 */
    @Override
	protected int[] getAsyncMessageFilter() {
        return messageFilter;
    }

    /**
	 *
	 *
	 * @param service
	 */
    public void acceptService(final Service service) {
        acceptServices.put(service.getServiceName(), service);
    }

    private void sendUserAuthFailure(final boolean success) throws IOException {
        if (!success) {
        	for (final AuthenticationProtocolListener listener : listeners) {
        		listener.onAuthenticationFailed();
        	}
        }

        final String auths = StringUtil.current().asString(availableAuths.toArray(new String[0]));

        if (log.isDebugEnabled()) log.debug("Sending auth result (auths: "+auths+", success : " + success + ")");

        final SshMsgUserAuthFailure reply = new SshMsgUserAuthFailure(auths, success);
        transport.sendMessage(reply, this);
    }

    /**
 *
 */
    @Override
	protected void onStop() {
        try {
            // If authentication succeeded then wait for the
            // disconnect and logoff the user
            if (completed) {
                try {
                    transport.getState().waitForState(TransportProtocolState.DISCONNECTED);
                } catch (final InterruptedException ex) {
                    log.warn("The authentication service was interrupted");
                }

                final NativeAuthenticationProvider nap = NativeAuthenticationProvider.getInstance();
                nap.logoffUser();
            }
        } catch (final IOException ex) {
            log.warn("Failed to logoff " + SshThread.getCurrentThreadUser());
        }
    }

    private void sendUserAuthSuccess() throws IOException {
    	for (final AuthenticationProtocolListener listener : listeners) {
    		listener.onAuthenticationComplete();
    	}

        final SshMsgUserAuthSuccess msg = new SshMsgUserAuthSuccess();
        final Service service = (Service) acceptServices.get(serviceToStart);
        service.init(Service.ACCEPTING_SERVICE, transport); //, nativeSettings);
        service.start();
        transport.sendMessage(msg, this);
        completed = true;
        stop();
    }

    private void onMsgUserAuthRequest(final SshMsgUserAuthRequest msg)
        throws IOException {
        if (msg.getMethodName().equals("none")) {
            sendUserAuthFailure(false);
        } else {
            if (attempts >= (ConfigurationLoader.getConfiguration(
                        ServerConfiguration.class)).getMaxAuthentications()) {
                // Too many authentication attempts
                transport.disconnect("Too many failed authentication attempts");
            } else {
                // If the service is supported then perfrom the authentication
                if (acceptServices.containsKey(msg.getServiceName())) {
                    final String method = msg.getMethodName();

                    if (availableAuths.contains(method)) {
                        final SshAuthenticationServer auth = SshAuthenticationServerFactory.newInstance(method);
                        serviceToStart = msg.getServiceName();

                        final int result = auth.authenticate(this, msg);

                        if (result == AuthenticationProtocolState.FAILED) {
                            sendUserAuthFailure(false);
                        } else if (result == AuthenticationProtocolState.COMPLETE) {
                            completedAuthentications.add(auth.getMethodName());

                            final ServerConfiguration sc = ConfigurationLoader.getConfiguration(ServerConfiguration.class);
                            for (final String required : sc.getRequiredAuthentications()) {
                                if (!completedAuthentications.contains(required)) {
                                    sendUserAuthFailure(true);
                                    return;
                                }
                            }

                            thread.setUsername(msg.getUsername());
                            sendUserAuthSuccess();
                        } else {
                            // Authentication probably returned READY as no completion
                            // evaluation was needed
                        }
                    } else {
                        sendUserAuthFailure(false);
                    }
                } else {
                    sendUserAuthFailure(false);
                }

                attempts++;
            }
        }
    }

	public ConnectionProtocol getConnectionProtocol() {
		final ConnectionProtocol protocol = (ConnectionProtocol) acceptServices.get(ConnectionProtocol.SERVICE_NAME);
		if (protocol == null) {
			log.warn("No connection protocol found on authentication protocol");
		}
		return protocol;
	}
}
