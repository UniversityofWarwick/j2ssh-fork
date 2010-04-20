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
package com.sshtools.j2ssh.net;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.13 $
 */
public interface TransportProvider {
    /**
     *
     *
     * @throws IOException
     */
    public void close() throws IOException;

    //public boolean isConnected();
    public ReadableByteChannel getReadableByteChannel() throws IOException;

    /**
     *
     *
     * @return
     *
     * @throws IOException
     */
    public WritableByteChannel getWritableByteChannel() throws IOException;

    /**
     *
     *
     * @return
     */
    public String getProviderDetail();
    
    /**
     * @return Whether this transport provider connects to a remote InetAddress
     */
    boolean isUsingInetAddress();
    
    /**
     * Returns the remote address <b>Only</b> if {@link #isAddressBased()} returns
     * true.
     */
    InetAddress getRemoteAddress();
}
