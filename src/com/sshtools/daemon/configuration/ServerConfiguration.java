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
package com.sshtools.daemon.configuration;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.sshtools.daemon.session.SessionChannelServer;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.transport.publickey.InvalidSshKeyException;
import com.sshtools.j2ssh.transport.publickey.SshPrivateKey;
import com.sshtools.j2ssh.transport.publickey.SshPrivateKeyFile;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.12 $
 */
public class ServerConfiguration extends DefaultHandler {
    private static Log log = LogFactory.getLog(ServerConfiguration.class);
    private final Map allowedSubsystems = new HashMap();
    private final Map serverHostKeys = new HashMap();
    private final List<String> allowedAuthentications = new ArrayList<String>();
    private final List<String> requiredAuthentications = new ArrayList<String>();
    private int commandPort = 12222;
    private int port = 22;
    private String listenAddress = "0.0.0.0";
    private int maxConnections = 10;
    private int maxAuthentications = 5;
    private String terminalProvider = "";
    private String authorizationFile = "authorization.xml";
    private String userConfigDirectory = "%D/.ssh2";
    private String authenticationBanner = "";
    private boolean allowTcpForwarding = true;
    private String currentElement = null;
    private int minimumWindowSpace;
    private int maximumWindowSpace;
    private Class sessionChannelImpl = SessionChannelServer.class; 

    /**
 * Creates a new ServerConfiguration object.
 *
 * @param in
 *
 * @throws SAXException
 * @throws ParserConfigurationException
 * @throws IOException
 */
    public ServerConfiguration(final InputStream in)
        throws SAXException, ParserConfigurationException, IOException {
        reload(in);
    }

    /**
 *
 *
 * @param in
 *
 * @throws SAXException
 * @throws ParserConfigurationException
 * @throws IOException
 */
    public void reload(final InputStream in)
        throws SAXException, ParserConfigurationException, IOException {
        allowedSubsystems.clear();
        serverHostKeys.clear();
        allowedAuthentications.clear();
        requiredAuthentications.clear();
        commandPort = 12222;
        port = 22;
        listenAddress = "0.0.0.0";
        maxConnections = 10;
        maxAuthentications = 5;
        terminalProvider = "";
        authorizationFile = "authorization.xml";
        userConfigDirectory = "%D/.ssh2";
        authenticationBanner = "";
        allowTcpForwarding = true;
        currentElement = null;

        minimumWindowSpace = 1024 * 1024; // 1MB
        maximumWindowSpace = 1024 * 1024 * 3; // 3MB

        final SAXParserFactory saxFactory = SAXParserFactory.newInstance();
        final SAXParser saxParser = saxFactory.newSAXParser();
        saxParser.parse(in, this);
    }

    /**
 *
 *
 * @param uri
 * @param localName
 * @param qname
 * @param attrs
 *
 * @throws SAXException
 */
    @Override
	public void startElement(final String uri, final String localName, final String qname,
        final Attributes attrs) throws SAXException {
        if (currentElement == null) {
            if (!qname.equals("ServerConfiguration")) {
                throw new SAXException("Unexpected root element " + qname);
            }
        } else {
            if (currentElement.equals("ServerConfiguration")) {
                if (qname.equals("ServerHostKey")) {
                    //String algorithm = attrs.getValue("AlgorithmName");
                    String privateKey = attrs.getValue("PrivateKeyFile");

                    if (privateKey == null) {
                        throw new SAXException(
                            "Required attributes missing from <ServerHostKey> element");
                    }

                    log.debug("ServerHostKey PrivateKeyFile=" + privateKey);

                    File f = new File(privateKey);

                    if (!f.exists()) {
                        privateKey = ConfigurationLoader.getConfigurationDirectory() +
                            privateKey;
                        f = new File(privateKey);
                    }

                    try {
                        if (f.exists()) {
                            final SshPrivateKeyFile pkf = SshPrivateKeyFile.parse(f);
                            final SshPrivateKey key = pkf.toPrivateKey(null);
                            serverHostKeys.put(key.getAlgorithmName(), key);
                        } else {
                            log.warn("Private key file '" + privateKey +
                                "' could not be found");
                        }
                    } catch (final InvalidSshKeyException ex) {
                        log.warn("Failed to load private key '" + privateKey, ex);
                    } catch (final IOException ioe) {
                        log.warn("Failed to load private key '" + privateKey,
                            ioe);
                    }
                } else if (qname.equals("Subsystem")) {
                    final String type = attrs.getValue("Type");
                    final String name = attrs.getValue("Name");
                    final String provider = attrs.getValue("Provider");

                    if ((type == null) || (name == null) || (provider == null)) {
                        throw new SAXException(
                            "Required attributes missing from <Subsystem> element");
                    }

                    log.debug("Subsystem Type=" + type + " Name=" + name +
                        " Provider=" + provider);
                    allowedSubsystems.put(name,
                        new AllowedSubsystem(type, name, provider));
                } else if (!qname.equals("AuthenticationBanner") &&
                        !qname.equals("MaxConnections") &&
                        !qname.equals("MaxAuthentications") &&
                        !qname.equals("ListenAddress") &&
                        !qname.equals("Port") && !qname.equals("CommandPort") &&
                        !qname.equals("TerminalProvider") &&
                        !qname.equals("AllowedAuthentication") &&
                        !qname.equals("RequiredAuthentication") &&
                        !qname.equals("AuthorizationFile") &&
                        !qname.equals("UserConfigDirectory") &&
                        !qname.equals("AllowTcpForwarding") &&
                        !qname.equals("MinimumWindowSpace") &&
                        !qname.equals("MaximumWindowSpace")) {
                    throw new SAXException("Unexpected <" + qname +
                        "> element after SshAPIConfiguration");
                }
            }
        }

        currentElement = qname;
    }

    /**
 *
 *
 * @param ch
 * @param start
 * @param length
 *
 * @throws SAXException
 */
    @Override
	public void characters(final char[] ch, final int start, final int length)
        throws SAXException {
        final String value = new String(ch, start, length);

        if (currentElement != null) {
            if (currentElement.equals("AuthenticationBanner")) {
                authenticationBanner = value;
                log.debug("AuthenticationBanner=" + authenticationBanner);
            } else if (currentElement.equals("MaxConnections")) {
                maxConnections = Integer.parseInt(value);
                log.debug("MaxConnections=" + value);
            } else if (currentElement.equals("ListenAddress")) {
                listenAddress = value;
                log.debug("ListenAddress=" + listenAddress);
            } else if (currentElement.equals("Port")) {
                port = Integer.parseInt(value);
                log.debug("Port=" + value);
            } else if (currentElement.equals("CommandPort")) {
                commandPort = Integer.parseInt(value);
                log.debug("CommandPort=" + value);
            } else if (currentElement.equals("TerminalProvider")) {
                terminalProvider = value;
                log.debug("TerminalProvider=" + terminalProvider);
            } else if (currentElement.equals("AllowedAuthentication")) {
                if (!allowedAuthentications.contains(value)) {
                    allowedAuthentications.add(value);
                    log.debug("AllowedAuthentication=" + value);
                }
            } else if (currentElement.equals("RequiredAuthentication")) {
                if (!requiredAuthentications.contains(value)) {
                    requiredAuthentications.add(value);
                    log.debug("RequiredAuthentication=" + value);
                }
            } else if (currentElement.equals("AuthorizationFile")) {
                authorizationFile = value;
                log.debug("AuthorizationFile=" + authorizationFile);
            } else if (currentElement.equals("UserConfigDirectory")) {
                userConfigDirectory = value;
                log.debug("UserConfigDirectory=" + userConfigDirectory);
            } else if (currentElement.equals("SessionChannelImpl")) {
                try {
                    sessionChannelImpl = ConfigurationLoader.getExtensionClass(value);
                } catch (final Exception e) {
                    log.error("Failed to load SessionChannelImpl " + value, e);
                }
            } else if (currentElement.equals("MaxAuthentications")) {
                maxAuthentications = Integer.parseInt(value);
                log.debug("MaxAuthentications=" + value);
            } else if (currentElement.equals("AllowTcpForwarding")) {
                allowTcpForwarding = Boolean.valueOf(value).booleanValue();
            } else if (currentElement.equals("MinimumWindowSpace")) {
            	minimumWindowSpace = Integer.parseInt(value);
            	log.debug("MinimumWindowSpace set to " + minimumWindowSpace);
            } else if (currentElement.equals("MaximumWindowSpace")) {
            	maximumWindowSpace = Integer.parseInt(value);
            	log.debug("MaximumWindowSpace set to " + maximumWindowSpace);
            }
        }
    }

    /**
 *
 *
 * @param uri
 * @param localName
 * @param qname
 *
 * @throws SAXException
 */
    @Override
	public void endElement(final String uri, final String localName, final String qname)
        throws SAXException {
        if (currentElement != null) {
            if (!currentElement.equals(qname)) {
                throw new SAXException("Unexpected end element found <" +
                    qname + ">");
            } else if (currentElement.equals("ServerConfiguration")) {
                currentElement = null;
            } else if (currentElement.equals("AuthenticationBanner") ||
                    currentElement.equals("ServerHostKey") ||
                    currentElement.equals("Subsystem") ||
                    currentElement.equals("MaxConnections") ||
                    currentElement.equals("MaxAuthentications") ||
                    currentElement.equals("ListenAddress") ||
                    currentElement.equals("Port") ||
                    currentElement.equals("CommandPort") ||
                    currentElement.equals("TerminalProvider") ||
                    currentElement.equals("AllowedAuthentication") ||
                    currentElement.equals("RequiredAuthentication") ||
                    currentElement.equals("AuthorizationFile") ||
                    currentElement.equals("UserConfigDirectory") ||
                    currentElement.equals("AllowTcpForwarding") ||
                    currentElement.equals("MinimumWindowSpace") ||
                    currentElement.equals("MaximumWindowSpace")) {
                currentElement = "ServerConfiguration";
            }
        } else {
            throw new SAXException("Unexpected end element <" + qname +
                "> found");
        }
    }

    /**
 *
 *
 * @return
 */
    public List<String> getRequiredAuthentications() {
        return requiredAuthentications;
    }

    /**
 *
 *
 * @return
 */
    public List<String> getAllowedAuthentications() {
        return allowedAuthentications;
    }

    /**
 *
 *
 * @return
 */
    public boolean getAllowTcpForwarding() {
        return allowTcpForwarding;
    }

    /**
 *
 *
 * @return
 */
    public String getAuthenticationBanner() {
        return authenticationBanner;
    }

    /**
 *
 *
 * @return
 */
    public int getCommandPort() {
        return commandPort;
    }

    /**
 *
 *
 * @return
 */
    public String getUserConfigDirectory() {
        return userConfigDirectory;
    }

    /**
 *
 *
 * @return
 */
    public String getAuthorizationFile() {
        return authorizationFile;
    }

    /**
 *
 *
 * @return
 */
    public String getListenAddress() {
        return listenAddress;
    }

    /**
 *
 *
 * @return
 */
    public int getMaxConnections() {
        return maxConnections;
    }

    /**
 *
 *
 * @return
 */
    public int getMaxAuthentications() {
        return maxAuthentications;
    }

    /**
 *
 *
 * @return
 */
    public int getPort() {
        return port;
    }

    /*public Class getSessionChannelImpl() {
 return sessionChannelImpl;
  }*/
    public Map getServerHostKeys() {
        return serverHostKeys;
    }

    /**
 *
 *
 * @return
 */
    public Map getSubsystems() {
        return allowedSubsystems;
    }

    /**
 *
 *
 * @return
 */
    public String getTerminalProvider() {
        return terminalProvider;
    }

    /**
 *
 *
 * @return
 */
    @Override
	public String toString() {
        final StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<!-- Server configuration file - If filenames are not absolute they are assummed to be in the same directory as this configuration file. -->\n");
        xml.append("<ServerConfiguration>\n");
        xml.append("   <!-- The available host keys for server authentication -->\n");

        Map.Entry entry;
        Iterator it = serverHostKeys.entrySet().iterator();

        while (it.hasNext()) {
            entry = (Map.Entry) it.next();
            xml.append("   <ServerHostKey PrivateKeyFile=\"" + entry.getValue() +
            "\"/>\n");
        }

        xml.append("   <!-- Add any number of subsystem elements here -->\n");

        AllowedSubsystem subsystem;
        it = allowedSubsystems.entrySet().iterator();

        while (it.hasNext()) {
            subsystem = (AllowedSubsystem) ((Map.Entry) it.next()).getValue();
            xml.append("   <Subsystem Name=\"" + subsystem.getName() +
            "\" Type=\"" + subsystem.getType() + "\" Provider=\"" +
            subsystem.getProvider() + "\"/>\n");
        }

        xml.append("   <!-- Display the following authentication banner before authentication -->\n");
        xml.append("   <AuthenticationBanner>" + authenticationBanner +
        "</AuthenticationBanner>\n");
        xml.append("   <!-- The maximum number of connected sessions available -->\n");
        xml.append("   <MaxConnections>" + String.valueOf(maxConnections) +
        "</MaxConnections>\n");
        xml.append("   <!-- The maximum number of authentication attemtps for each connection -->\n");
        element(xml, "MaxAuthentications", maxAuthentications);
        xml.append("   <!-- Bind to the following address to listen for connections -->\n");
        element(xml, "ListenAddress", listenAddress);
        xml.append("   <!-- The port to listen to -->\n");
        element(xml, "Port", port);
        xml.append("   <!-- Listen on the following port (on localhost) for server commands such as stop -->\n");
        xml.append("   <CommandPort>" + String.valueOf(commandPort) +
        "</CommandPort>\n");
        xml.append("   <!-- Specify the executable that provides the default shell -->\n");
        xml.append("   <TerminalProvider>" + terminalProvider +
        "</TerminalProvider>\n");
        xml.append("   <!-- Specify any number of allowed authentications -->\n");
        it = allowedAuthentications.iterator();

        while (it.hasNext()) {
            xml.append("   <AllowedAuthentication>" + it.next().toString() +
            "</AllowedAuthentication>\n");
        }

        xml.append("   <!-- Specify any number of required authentications -->\n");
        for (final String auth : requiredAuthentications) {
            xml .append("   <RequiredAuthentication>" + auth +
            "</RequiredAuthentication>\n");
        }

        xml.append("   <!-- The users authorizations file -->\n");
        xml.append("   <AuthorizationFile>" + authorizationFile +
        "</AuthorizationFile>\n");
        xml.append("   <!-- The users configuration directory where files such as AuthorizationFile are found. For users home directory specify %D For users name specify %U  -->\n");
        xml.append("   <UserConfigDirectory>" + userConfigDirectory + "</UserConfigDirectory>\n");
        xml.append("   <AllowTcpForwarding>" + String.valueOf(allowTcpForwarding) + "</AllowTcpForwarding>\n");

        comment(xml, "Window space limits for session channel server");
        element(xml, "MinimumWindowSpace", minimumWindowSpace);
        element(xml, "MaximumWindowSpace", maximumWindowSpace);

        xml.append("</ServerConfiguration>\n");

        return xml.toString();
    }

	public final int getMinimumWindowSpace() {
		return minimumWindowSpace;
	}

	public final int getMaximumWindowSpace() {
		return maximumWindowSpace;
	}

	private static void comment(final StringBuilder sb, final String comment) {
		sb.append("  <!-- ");
		sb.append(comment);
		sb.append("-->\n");
	}

	private static void element(final StringBuilder sb, final String name, final Object value) {
		sb.append("  <");
		sb.append(name);
		sb.append(">\n");
        sb.append(value);
        sb.append("\n");
        sb.append("  </");
		sb.append(name);
		sb.append(">\n");
	}
}
