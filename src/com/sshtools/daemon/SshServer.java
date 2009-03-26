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
package com.sshtools.daemon;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.daemon.authentication.AuthenticationProtocolServer;
import com.sshtools.daemon.configuration.PlatformConfiguration;
import com.sshtools.daemon.configuration.ServerConfiguration;
import com.sshtools.daemon.transport.TransportProtocolServer;
import com.sshtools.j2ssh.SshException;
import com.sshtools.j2ssh.SshThread;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.configuration.SshConnectionProperties;
import com.sshtools.j2ssh.connection.ConnectionProtocol;
import com.sshtools.j2ssh.net.ConnectedSocketChannelTransportProvider;
import com.sshtools.j2ssh.transport.TransportProtocol;
import com.sshtools.j2ssh.transport.TransportProtocolEventAdapter;
import com.sshtools.j2ssh.transport.TransportProtocolEventHandler;
import com.sshtools.j2ssh.util.StartStopState;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.18 $
 */
public abstract class SshServer {
    private static Log log = LogFactory.getLog(SshServer.class);
    private ConnectionListener listener = null;
    //private ServerSocket server = null;
    private boolean shutdown = false;
    private ServerSocket commandServerSocket;
    
    private boolean acceptingConnections = true;

	/**  */
    protected List<TransportProtocolServer> activeConnections = new LinkedList<TransportProtocolServer>();
    Thread thread;

    /**
 * Creates a new SshServer object.
 *
 * @throws IOException
 * @throws SshException
 */
    public SshServer() throws IOException {
        String serverId = System.getProperty("sshtools.serverid");

        if (serverId != null) {
            TransportProtocolServer.SOFTWARE_VERSION_COMMENTS = serverId;
        }

        if (!ConfigurationLoader.isConfigurationAvailable(
                    ServerConfiguration.class)) {
            throw new SshException("Server configuration not available!");
        }

        if (!ConfigurationLoader.isConfigurationAvailable(
                    PlatformConfiguration.class)) {
            throw new SshException("Platform configuration not available");
        }

        if (((ServerConfiguration) ConfigurationLoader.getConfiguration(
                    ServerConfiguration.class)).getServerHostKeys().size() <= 0) {
            throw new SshException(
                "Server cannot start because there are no server host keys available");
        }
    }
    

    public boolean isAcceptingConnections() {
		return acceptingConnections;
	}

    /**
     * Default is true. If set to false, will refuse any new connections.
     * This may be useful when you want to shut down the server gracefully
     * by waiting for existing connections to end, without allowing new ones.
     */
	public void setAcceptingConnections(boolean acceptingConnections) {
		this.acceptingConnections = acceptingConnections;
		log.info("Accepting connections changed to: " + acceptingConnections);
	}


    public void startServer() throws IOException {
        log.info("Starting server");
        shutdown = false;
        startServerSocket();
        
        
        thread = new Thread(new Runnable() {
                    public void run() {
                        try {
                            startCommandSocket();
                        } catch (IOException ex) {
                            log.info("Failed to start command socket", ex);

                            try {
                                stopServer("The command socket failed to start");
                            } catch (IOException ex1) {
                            }
                        }
                    }
                });
        thread.start();

        try {
            thread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
 *
 *
 * @param command
 * @param client
 *
 * @throws IOException
 */
    protected void processCommand(int command, Socket client)
        throws IOException {
        if (command == 0x3a) {
            int len = client.getInputStream().read();
            byte[] msg = new byte[len];
            client.getInputStream().read(msg);
            stopServer(new String(msg, "UTF8"));
        }
    }

    /**
	 * Listen on the command socket which really just listens for a command to stop the server.
	 */
    protected void startCommandSocket() throws IOException {
        try {
        	int commandPort = ConfigurationLoader.getConfiguration(ServerConfiguration.class).getCommandPort();
            commandServerSocket = new ServerSocket(commandPort, 50, InetAddress.getLocalHost());

            Socket client;

            while ((client = commandServerSocket.accept()) != null) {
                log.info("Command request received");

                // Read and process the command
                processCommand(client.getInputStream().read(), client);
                client.close();

                if (shutdown) {
                    break;
                }
            }

            commandServerSocket.close();
        } catch (Exception e) {
            if (!shutdown) {
                log.fatal("The command socket failed", e);
            }
        }
    }

    /**
	 *	The server socket is what listens for most of the data received, and handles
	 *	messages.
	 */
    protected void startServerSocket() throws IOException {
        ServerConfiguration serverConfiguration = (ServerConfiguration) ConfigurationLoader.getConfiguration(
		    ServerConfiguration.class);
		InetAddress address = InetAddress.getByName(serverConfiguration.getListenAddress());
		int port = serverConfiguration.getPort();
		listener = new ConnectionListener(address, port);
        listener.start();
    }

    /**
 *
 *
 * @param msg
 *
 * @throws IOException
 */
    public void stopServer(String msg) throws IOException {
        log.info("Shutting down server");
        shutdown = true;
        log.debug(msg);
        shutdown(msg);
        listener.stop();
        log.debug("Stopping command server");

        try {
            if (commandServerSocket != null) {
                commandServerSocket.close();
            }
        } catch (IOException ioe) {
            log.error(ioe);
        }
    }

 
    protected abstract void shutdown(String msg);

    /**
     * 
     */
    protected abstract void configureServices(ConnectionProtocol connection)
        throws IOException;

 
    protected void refuseSession(SocketChannel socketChannel) throws IOException {
    	if (log.isDebugEnabled()) log.debug("Refuse session");
        TransportProtocolServer transport = new TransportProtocolServer(true);
        transport.startTransportProtocol(new ConnectedSocketChannelTransportProvider(socketChannel), new SshConnectionProperties());
    }

    protected TransportProtocolServer createSession(SocketChannel socketChannel)
        throws IOException {
    	if (log.isDebugEnabled()) log.debug("Initializing connection");
        InetAddress address = socketChannel.socket().getInetAddress();
        if (log.isDebugEnabled()) log.debug("Remote Address: " + address.toString());

        TransportProtocolServer transport = new TransportProtocolServer();
        AuthenticationProtocolServer authentication = new AuthenticationProtocolServer();
        ConnectionProtocol connection = new ConnectionProtocol();

        ConnectedSocketChannelTransportProvider transportProvider 
				= new ConnectedSocketChannelTransportProvider(socketChannel);
        
        // Configure the connections services
        configureServices(connection);

        // Allow the Connection Protocol to be accepted by the Authentication Protocol
        authentication.acceptService(connection);

        // Allow the Authentication Protocol to be accepted by the Transport Protocol
        transport.acceptService(authentication);
		transport.startTransportProtocol(transportProvider, new SshConnectionProperties());

        return transport;
    }

    class ConnectionListener implements Runnable {
        private Log log = LogFactory.getLog(ConnectionListener.class);
        private ServerSocketChannel server;
        private InetAddress listenAddress;
        private Thread thread;
        private int maxConnections;
        private int port;
        private StartStopState state = new StartStopState(StartStopState.STOPPED);

        public ConnectionListener(InetAddress listenAddress, int port) {
            this.port = port;
            this.listenAddress = listenAddress;
        }

        public void run() {
            try {
                log.debug("Starting connection listener thread on address " + listenAddress);
                state.setValue(StartStopState.STARTED);
                
                //server = new ServerSocket(port, 0, listenAddress);
                //Socket socket;
                
                server = ServerSocketChannel.open();
                server.socket().bind(new InetSocketAddress(listenAddress, port), 0);
                log.debug("ServerSocketChannel opened. blocking: " + server.isBlocking());

                SocketChannel socketChannel;
                maxConnections = ConfigurationLoader.getConfiguration(ServerConfiguration.class).getMaxConnections();

                boolean refuse = false;
                TransportProtocolEventHandler eventHandler = new TransportProtocolEventAdapter() {
                    public void onDisconnect(TransportProtocol transport) {
                        // Remove from our active channels list only if
                        // we're still connected (the thread cleans up
                        // when were exiting so this is to avoid any concurrent
                        // modification problems
                        if (state.getValue() != StartStopState.STOPPED) {
                            synchronized (activeConnections) {
                                log.info(transport.getUnderlyingProviderDetail() + " connection closed");
                                activeConnections.remove(transport);
                            }
                        }
                    }
                };

                try {
                    while (((socketChannel = server.accept()) != null) &&
                            (state.getValue() == StartStopState.STARTED)) {
                        log.debug("New connection requested");
                        
                        Socket socket = socketChannel.socket();

                        if (!isAcceptingConnections() || maxConnections < activeConnections.size()) {
                            refuseSession(socketChannel);
                        } else {
                            TransportProtocolServer transport = createSession(socketChannel);
                            log.info("Monitoring active session from " +
                            		socket.getInetAddress().toString());

                            synchronized (activeConnections) {
                                activeConnections.add(transport);
                            }

                            transport.addEventHandler(eventHandler);
                        }
                    }
                } catch (IOException ex) {
                    if (state.getValue() != StartStopState.STOPPED) {
                        log.info("The server was shutdown unexpectedly", ex);
                    }
                }

                state.setValue(StartStopState.STOPPED);

                // Closing all connections
                log.info("Disconnecting active sessions");

                for (TransportProtocolServer s : activeConnections) {
                    s.disconnect("The server is shutting down");
                }

                listener = null;
                log.info("Exiting connection listener thread");
            } catch (IOException ex) {
                log.info("The server thread failed", ex);
            } finally {
                thread = null;
            }

        }

        public void start() {
            thread = new SshThread(this, "Connection listener", true);
            thread.start();
        }

        public void stop() {
            try {
                state.setValue(StartStopState.STOPPED);
                
                if (server != null) {
                	server.close();
                } else {
                	log.debug("server was null. might be okay");
                }

                if (thread != null) {
                    thread.interrupt();
                }
            } catch (IOException ioe) {
                log.warn("The listening socket reported an error during shutdown", ioe);
            }
        }
    }

	public final Collection<TransportProtocolServer> getActiveConnections() {
		return Collections.unmodifiableCollection(activeConnections);
	}
}
