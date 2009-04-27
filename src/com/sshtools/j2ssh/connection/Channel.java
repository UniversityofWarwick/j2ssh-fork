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
package com.sshtools.j2ssh.connection;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An SSH channel. Each SSH connection supports multiple channels going through it.
 */
public abstract class Channel {
	private static Log log = LogFactory.getLog(Channel.class);

	protected ChannelDataWindow localWindow = new ChannelDataWindow("local");
	protected ChannelDataWindow remoteWindow = new ChannelDataWindow("remote");
	
	protected ConnectionProtocol connection;

	protected long localChannelId;
	protected long localPacketSize;
	protected long remoteChannelId;
	protected long remotePacketSize;

	protected final ChannelState state = new ChannelState();
	private boolean isLocalEOF = false;
	private boolean isRemoteEOF = false;
	private boolean localHasClosed = false;
	private boolean remoteHasClosed = false;
	private String name = "Unnamed Channel";
	private Collection<ChannelEventListener> eventListeners = new ArrayList<ChannelEventListener>();

	public Channel() {
		this.localPacketSize = getMaximumPacketSize();
		
		// Used to set local window size here, but this made it impossible for subclasses to set up values in their
		// constructor.
	}

	public abstract byte[] getChannelOpenData();

	public abstract byte[] getChannelConfirmationData();

	public abstract String getChannelType();

	/**
	 * Though local window space can go all the way to 0,
	 * we will send a message to refill it as soon as it drops
	 * below this minimum. This should help to avoid pauses
	 * as the client waits for our window to be refilled.
	 */
	protected abstract int getMinimumWindowSpace();


   /**
    * The maximum local window space to assign is the
    * largest amount of data we can receive before needing
    * to send back a channel window adjust message.
    * 
    * Making this too small results in timeouts
    * on some clients.
    */
	protected abstract int getMaximumWindowSpace();
	
	protected abstract int getMaximumPacketSize();

	protected abstract void onChannelData(SshMsgChannelData msg)
			throws IOException;

	/**
	 * 
	 * 
	 * @param msg
	 * 
	 * @throws IOException
	 */
	protected synchronized void processChannelData(SshMsgChannelData msg) throws IOException {
		if (!isClosed()) {
			/**
			 * We aren't handling where there is more data than window space.
			 * We are just carrying on (and letting the space drop below zero)
			 * because there's no real reason to stop. A window adjust message
			 * will get sent to replenish the window, and then everything
			 * will be fine.
			 */
			long windowSpace = localWindow.consumeWindowSpace(msg
					.getChannelData().length);

			if (windowSpace < getMinimumWindowSpace()) {
				if (log.isDebugEnabled()) {
					log.debug("Channel " + String.valueOf(localChannelId)
							+ " requires more window space [" + name + "]");
				}
				long increase = getMaximumWindowSpace() - windowSpace;
				localWindow.increaseWindowSpace(increase);
				connection.sendChannelWindowAdjust(this, increase);
			}

			onChannelData(msg);

			for (ChannelEventListener eventListener : eventListeners) {
				if (eventListener != null) {
					eventListener.onDataReceived(this, msg.getChannelData());
				}
			}
		} else {
			throw new IOException(
					"Channel data received but channel is closed [" + name
							+ "]");
		}
		
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public synchronized boolean isClosed() {
		return state.getValue() == ChannelState.CHANNEL_CLOSED;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public synchronized boolean isOpen() {
		return state.getValue() == ChannelState.CHANNEL_OPEN;
	}

	/**
	 * 
	 * 
	 * @param data
	 * 
	 * @throws IOException
	 */
	protected void sendChannelData(byte[] data)
			throws IOException {
		if (!connection.isConnected()) {
			throw new IOException("The connection has been closed [" + name
					+ "]");
		}

		if (!isClosed()) {
			connection.sendChannelData(this, data);

			for (ChannelEventListener eventListener : eventListeners) {
				if (eventListener != null) {
					eventListener.onDataSent(this, data);
				}
			}
		} else {
			throw new IOException("The channel is closed [" + name + "]");
		}
	}

	/**
	 * 
	 * 
	 * @param type
	 * @param data
	 * 
	 * @throws IOException
	 */
	protected/* synchronized */void sendChannelExtData(int type, byte[] data)
			throws IOException {
		if (!connection.isConnected()) {
			throw new IOException("The connection has been closed [" + name
					+ "]");
		}

		if (!isClosed()) {
			connection.sendChannelExtData(this, type, data);

			for (ChannelEventListener eventListener : eventListeners) {
				if (eventListener != null) {
					eventListener.onDataSent(this, data);
				}
			}
		} else {
			throw new IOException("The channel is closed [" + name + "]");
		}
	}

	/**
	 * 
	 * 
	 * @param msg
	 * 
	 * @throws IOException
	 */
	protected abstract void onChannelExtData(SshMsgChannelExtendedData msg)
			throws IOException;

	/**
	 * 
	 * 
	 * @param msg
	 * 
	 * @throws IOException
	 */
	protected void processChannelData(SshMsgChannelExtendedData msg)
			throws IOException {
		synchronized (state) {
//			if (msg.getChannelData().length > localWindow.getWindowSpace()) {
//				throw new IOException(
//						"More data received than is allowed by the channel data window ["
//								+ name + "]");
//			}
			
			long windowSpace = localWindow.consumeWindowSpace(msg
					.getChannelData().length);

			if (windowSpace < getMinimumWindowSpace()) {
				if (log.isDebugEnabled()) {
					log.debug("Channel " + String.valueOf(localChannelId)
							+ " requires more window space [" + name + "]");
				}

				long increase = getMaximumWindowSpace() - windowSpace;
				localWindow.increaseWindowSpace(increase);
				connection.sendChannelWindowAdjust(this, increase);
			}

			onChannelExtData(msg);

			for (ChannelEventListener eventListener : eventListeners) {
				if (eventListener != null) {
					eventListener.onDataReceived(this, msg.getChannelData());
				}
			}
		}
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public long getLocalChannelId() {
		return localChannelId;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public long getLocalPacketSize() {
		return localPacketSize;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public ChannelDataWindow getLocalWindow() {
		return localWindow;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public long getRemoteChannelId() {
		return remoteChannelId;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public long getRemotePacketSize() {
		return remotePacketSize;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public ChannelDataWindow getRemoteWindow() {
		return remoteWindow;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public ChannelState getState() {
		return state;
	}

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	public void close() throws IOException {
		synchronized (state) {
			if (isOpen()) {
				if ((connection != null) && !localHasClosed
						&& connection.isConnected()) {
					connection.closeChannel(this);
				}

				localHasClosed = true;

				if (log.isDebugEnabled()) {
					log.debug("Connection is "
							+ ((connection == null) ? "null" : (connection
									.isConnected() ? "connected"
									: "not connected")));
				}

				if (remoteHasClosed
						|| ((connection == null) || !connection.isConnected())) {
					log.info("Finalizing channel close");
					finalizeClose();
				}
			}
		}
	}

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	protected void remoteClose() throws IOException {
		log.info("Remote side is closing channel");

		synchronized (state) {
			remoteHasClosed = true;
			close();
		}
	}

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	protected void finalizeClose() throws IOException {
		synchronized (state) {
			state.setValue(ChannelState.CHANNEL_CLOSED);
			onChannelClose();
			
			for (ChannelEventListener eventListener : eventListeners) {
				if (eventListener != null) {
					eventListener.onChannelClose(this);
				}
			}

			if (connection != null) {
				connection.freeChannel(this);
			}
		}
	}

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	public void setLocalEOF() throws IOException {
		synchronized (state) {
			isLocalEOF = true;
			connection.sendChannelEOF(this);
		}
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public boolean isLocalEOF() {
		return isLocalEOF;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public boolean isRemoteEOF() {
		return isRemoteEOF;
	}

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	protected void setRemoteEOF() throws IOException {
		synchronized (state) {
			isRemoteEOF = true;
			onChannelEOF();

			for (ChannelEventListener eventListener : eventListeners) {
				if (eventListener != null) {
					eventListener.onChannelEOF(this);
				}
			}
		}
	}

	/**
	 * 
	 * 
	 * @param eventListener
	 */
	public void addEventListener(ChannelEventListener eventListener) {
		synchronized(state) {
			eventListeners.add(eventListener);
		}
	}

	/**
	 * 
	 * 
	 * @param connection
	 * @param localChannelId
	 * @param senderChannelId
	 * @param initialWindowSize
	 * @param maximumPacketSize
	 * 
	 * @throws IOException
	 */
	protected void init(ConnectionProtocol connection, long localChannelId,
			long senderChannelId, long initialWindowSize, long maximumPacketSize)
			throws IOException {
		this.localWindow.increaseWindowSpace(getMaximumWindowSpace());
		
		this.localChannelId = localChannelId;
		this.remoteChannelId = senderChannelId;
		this.remotePacketSize = maximumPacketSize;
		this.remoteWindow.increaseWindowSpace(initialWindowSize);
		this.connection = connection;

		synchronized (state) {
			state.setValue(ChannelState.CHANNEL_OPEN);
		}
	}

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	protected void open() throws IOException {
		synchronized (state) {
			state.setValue(ChannelState.CHANNEL_OPEN);
			onChannelOpen();

			for (ChannelEventListener eventListener : eventListeners) {
				if (eventListener != null) {
					eventListener.onChannelOpen(this);
				}
			}
		}
	}

	/**
	 * 
	 * 
	 * @param connection
	 * @param localChannelId
	 * @param senderChannelId
	 * @param initialWindowSize
	 * @param maximumPacketSize
	 * @param eventListener
	 * 
	 * @throws IOException
	 */
	protected void init(ConnectionProtocol connection, long localChannelId,
			long senderChannelId, long initialWindowSize,
			long maximumPacketSize, ChannelEventListener eventListener)
			throws IOException {
		if (eventListener != null) {
			addEventListener(eventListener);
		}

		init(connection, localChannelId, senderChannelId, initialWindowSize,
				maximumPacketSize);
	}

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	protected abstract void onChannelClose() throws IOException;

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	protected abstract void onChannelEOF() throws IOException;

	/**
	 * 
	 * 
	 * @throws IOException
	 */
	protected abstract void onChannelOpen() throws IOException;

	/**
	 * 
	 * 
	 * @param requestType
	 * @param wantReply
	 * @param requestData
	 * 
	 * @throws IOException
	 */
	protected abstract void onChannelRequest(String requestType,
			boolean wantReply, byte[] requestData) throws IOException;

	/**
	 * 
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * 
	 * 
	 * @return
	 */
	public String getName() {
		return name;
	}
}
