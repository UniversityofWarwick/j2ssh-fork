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
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.WritableByteChannel;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds a SocketChannel rather than a Socket to provide transport. It does still
 * have a socket, but it uses NIO
 */
public class ConnectedSocketChannelTransportProvider implements TransportProvider {
    final SocketChannel socketChannel;
    
    
    public static final Log log = LogFactory.getLog(ConnectedSocketChannelTransportProvider.class);

    /**
     * Creates a new ConnectedSocketTransportProvider object.
     */
    public ConnectedSocketChannelTransportProvider(SocketChannel socketChannel) {
    	log.debug("Creating NIO SocketChannel backed transport provider");
        this.socketChannel = socketChannel;
        //this.socket = socketChannel.socket();
    }

    public void close() throws IOException {
    	log.debug("closing socket");
        socketChannel.close();
    }
    
    public ReadableByteChannel getReadableByteChannel() throws IOException {
    	return new ReadableByteChannel() {
			public int read(ByteBuffer dst) throws IOException {
				return socketChannel.read(dst);
			}

			public void close() throws IOException {
				socketChannel.close();
			}

			public boolean isOpen() {
				return socketChannel.isOpen();
			}
		};
    }
    
    public WritableByteChannel getWritableByteChannel() throws IOException {
    	return socketChannel;
    }

    public String getProviderDetail() {
        return socketChannel.toString();
    }

	@Override
	public boolean isUsingInetAddress() {
		return true;
	}

	@Override
    public InetAddress getRemoteAddress() {
    	return socketChannel.socket().getInetAddress();
    }
}
