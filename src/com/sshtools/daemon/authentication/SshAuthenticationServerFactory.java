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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.j2ssh.configuration.ConfigurationException;
import com.sshtools.j2ssh.configuration.ConfigurationLoader;
import com.sshtools.j2ssh.configuration.ExtensionAlgorithm;
import com.sshtools.j2ssh.configuration.SshAPIConfiguration;
import com.sshtools.j2ssh.transport.AlgorithmNotSupportedException;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.10 $
 */
public class SshAuthenticationServerFactory {
    private static Map<String, Class<? extends SshAuthenticationServer>> auths;
    private static Log log = LogFactory.getLog(SshAuthenticationServerFactory.class);

    /**  */
    public final static String AUTH_PASSWORD = "password";

    /**  */
    public final static String AUTH_PK = "publickey";

    /**  */
    public final static String AUTH_KBI = "keyboard-interactive";

    static {
        auths = new HashMap<String, Class<? extends SshAuthenticationServer>>();
        log.info("Loading supported authentication methods");
        auths.put(AUTH_PASSWORD, PasswordAuthenticationServer.class);
        auths.put(AUTH_PK, PublicKeyAuthenticationServer.class);
        auths.put(AUTH_KBI, KBIPasswordAuthenticationServer.class);

        try {
            if (ConfigurationLoader.isConfigurationAvailable(
                        SshAPIConfiguration.class)) {
                SshAPIConfiguration config = (SshAPIConfiguration) ConfigurationLoader.getConfiguration(SshAPIConfiguration.class);

                // Add the methods to our supported list
                for (ExtensionAlgorithm method : config.getAuthenticationExtensions()) {
                
                    String name = method.getAlgorithmName();

                    if (auths.containsKey(name)) {
                        log.debug("Standard authentication implementation for " +
                            name + " is being overidden by " +
                            method.getImplementationClass());
                    } else {
                        log.debug(name + " authentication is implemented by " +
                            method.getImplementationClass());
                    }

                    try {
                        Class cls = ConfigurationLoader.getExtensionClass(method.getImplementationClass());
                        Object obj = cls.newInstance();

                        if (obj instanceof SshAuthenticationServer) {
                            auths.put(name, cls);
                        }
                    } catch (Exception e) {
                        log.warn(
                            "Failed to load extension authentication implementation " +
                            method.getImplementationClass(), e);
                    }
                }
            }
        } catch (ConfigurationException ex) {
        }
    }

    /**
 * Creates a new SshAuthenticationServerFactory object.
 */
    protected SshAuthenticationServerFactory() {
    }

    /**
 *
 */
    public static void initialize() {
    }

    /**
 *
 *
 * @return
 */
    public static List<String> getSupportedMethods() {
        // Get the list of ciphers
        List<String> list = new ArrayList<String>(auths.keySet());

        // Return the list
        return list;
    }

    /**
 *
 *
 * @param methodName
 *
 * @return
 *
 * @throws AlgorithmNotSupportedException
 */
    public static SshAuthenticationServer newInstance(String methodName)
        throws AlgorithmNotSupportedException {
        try {
            return (SshAuthenticationServer) ((Class) auths.get(methodName)).newInstance();
        } catch (Exception e) {
            throw new AlgorithmNotSupportedException(methodName +
                " is not supported!");
        }
    }
}
