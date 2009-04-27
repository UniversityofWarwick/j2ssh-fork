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
package com.sshtools.daemon.subsystem;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.daemon.session.SessionChannelServer;
import com.sshtools.j2ssh.SshThread;
import com.sshtools.j2ssh.io.UnsignedInteger32;
import com.sshtools.j2ssh.sftp.IncompleteMessage;
import com.sshtools.j2ssh.sftp.SshFxpStatus;
import com.sshtools.j2ssh.sftp.UnrecognizedMessage;
import com.sshtools.j2ssh.subsystem.SubsystemInputStream;
import com.sshtools.j2ssh.subsystem.SubsystemMessage;
import com.sshtools.j2ssh.subsystem.SubsystemMessageStore;
import com.sshtools.j2ssh.subsystem.SubsystemOutputStream;
import com.sshtools.j2ssh.transport.MessageStoreEOFException;
import com.sshtools.j2ssh.util.StartStopState;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.12 $
 */
public abstract class SubsystemServer implements Runnable {
    private static Log log = LogFactory.getLog(SubsystemServer.class);
    private SubsystemMessageStore incoming = new SubsystemMessageStore("incoming");
    private SubsystemMessageStore outgoing = new SubsystemMessageStore("outgoing");
    private SubsystemInputStream in = new SubsystemInputStream(outgoing);
    private SubsystemOutputStream out = new SubsystemOutputStream(incoming);
    private SshThread thread;
    private StartStopState state = new StartStopState(StartStopState.STOPPED);

    /**  */
    protected SessionChannelServer session;

    /**
 * Creates a new SubsystemServer object.
 */
    public SubsystemServer() {
    	registerMessage(IncompleteMessage.FAKE_ID, IncompleteMessage.class);
    }

    /**
 *
 *
 * @param session
 */
    public void setSession(SessionChannelServer session) {
        this.session = session;
    }

    /**
 *
 *
 * @return
 *
 * @throws IOException
 */
    public InputStream getInputStream() throws IOException {
        return in;
    }

    /**
 *
 *
 * @return
 *
 * @throws IOException
 */
    public OutputStream getOutputStream() throws IOException {
        return out;
    }

    /**
 *
 */
    public void run() {
        state.setValue(StartStopState.STARTED);

        try {
            while (state.getValue() == StartStopState.STARTED) {
                SubsystemMessage msg = incoming.nextMessage();
                if (msg != null) {
                	if (msg instanceof UnrecognizedMessage) {
                		log.info("Returning FX_OP_UNSUPPORTED to unrecognized message type");
                		UnrecognizedMessage badMsg = (UnrecognizedMessage) msg;
                		SshFxpStatus statusMsg = new SshFxpStatus(badMsg.getId(),
                                new UnsignedInteger32(SshFxpStatus.STATUS_FX_OP_UNSUPPORTED),
                                "Unrecognized message type", "");
                		sendMessage(statusMsg);
                	} else {
	                	try {
	                		onMessageReceived(msg);
	                	} finally {
	                		msg.finish();
	                	}
                	}
                } else {
                	log.debug("Null message");
                }
            }
            log.debug("SubsystemServer finished");
        } catch (MessageStoreEOFException meof) {
        	if (state.getValue() == StartStopState.STARTED) {
        		log.warn("EOF in message store", meof);
        	}
        }

        thread = null;
    }

    /**
 *
 */
    public void start() {
        if (Thread.currentThread() instanceof SshThread) {
            thread = ((SshThread) Thread.currentThread()).cloneThread(this,
                    "SubsystemServer");
            thread.start();
        } else {
            log.error(
                "Subsystem Server must be called from within an SshThread context");
            stop();
        }
    }

    /**
 *
 */
    public void stop() {
        state.setValue(StartStopState.STOPPED);
        incoming.close();
        outgoing.close();
        if (thread != null) {
        	//Kick the message loop if waiting, so it can notice we're closing down
        	thread.interrupt();
        }
    }

    /**
 *
 *
 * @return
 */
    public StartStopState getState() {
        return state;
    }

    /**
	 *
	 *
	 * @param msg
	 */
    protected abstract void onMessageReceived(SubsystemMessage msg);

    /**
 *
 *
 * @param messageId
 * @param implementor
 */
    protected void registerMessage(int messageId, Class implementor) {
        incoming.registerMessage(messageId, implementor);
    }

    /**
 *
 *
 * @param msg
 */
    protected void sendMessage(SubsystemMessage msg) {
        outgoing.addMessage(msg);
    }
}
