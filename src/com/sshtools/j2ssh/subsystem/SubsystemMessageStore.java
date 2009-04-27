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
package com.sshtools.j2ssh.subsystem;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.j2ssh.sftp.UnrecognizedMessage;
import com.sshtools.j2ssh.transport.InvalidMessageException;
import com.sshtools.j2ssh.transport.MessageNotAvailableException;
import com.sshtools.j2ssh.transport.MessageStoreEOFException;
import com.sshtools.j2ssh.util.OpenClosedState;


/**
 * Stores messages. It is used for both incoming and outgoing messages,
 * so it may be populated by data from a SubsystemOutputStream, or it
 * can be populated and used by a SubsystemInputStream to read messages
 * to serialize and send.
 */
public class SubsystemMessageStore {
    private static Log log = LogFactory.getLog(SubsystemMessageStore.class);

    // List to hold messages as they are received

    /**  */
    protected List<SubsystemMessage> messages = new ArrayList<SubsystemMessage>();

    // Map to hold message implementation classes

    /**  */
    protected Map<Integer, Class> registeredMessages = new HashMap<Integer, Class>();
    private OpenClosedState state = new OpenClosedState(OpenClosedState.OPEN);

    private String name;
    
    /**
     * Creates a new SubsystemMessageStore object.
     */
    public SubsystemMessageStore(final String name) {
    	this.name = name;
    }

    /**
     *
     *
     * @param msg
     */
    public synchronized void addMessage(SubsystemMessage msg) {

        // Add the message
        messages.add(msg);

        // Notify the threads
        notifyAll();
    }

    /**
     *
     *
     * @param msgdata
     *
     * @throws InvalidMessageException
     */
    public synchronized void addMessage(byte[] msgdata)
        throws InvalidMessageException {
        try {
            Class impl = (Class) registeredMessages.get(new Integer(msgdata[0]));

            SubsystemMessage msg;
            if (impl == null) {
                msg = new UnrecognizedMessage();
                msg.fromByteArray(msgdata);
                if (log.isDebugEnabled()) log.debug("Received unrecognised message type " + ((UnrecognizedMessage)msg).getId());                
            } else {
	            msg = (SubsystemMessage) impl.newInstance();
	            msg.fromByteArray(msgdata);
            }
            addMessage(msg);

            return;
        } catch (IllegalAccessException iae) {
        } catch (InstantiationException ie) {
        }

        throw new InvalidMessageException("Could not instantiate message class");
    }

    /**
     *
     *
     * @return
     *
     * @throws MessageStoreEOFException
     */
    public synchronized SubsystemMessage nextMessage()
        throws MessageStoreEOFException {
        try {
            return nextMessage(0);
        } catch (MessageNotAvailableException mnae) {
            return null;
        }
    }


    public synchronized SubsystemMessage nextMessage(int timeout)
        throws MessageStoreEOFException, MessageNotAvailableException {
        // If there are no messages available then wait untill there are.
        timeout = (timeout > 0) ? timeout : 0;

        while (messages.size() <= 0 && state.getValue() == OpenClosedState.OPEN) {
            try {
            	//log.debug("SSMS "+name+" - Waiting");
                wait(timeout);

                if (timeout > 0) {
                    break;
                }
                //log.debug("SSMS "+name+" AWOKEN - " + messages.size());
            } catch (InterruptedException e) {
            	// Kicked to here when server is closing. The state should be
            	// set to closed so 
            }
        }

        if (state.getValue() != OpenClosedState.OPEN) {
            throw new MessageStoreEOFException();
        }

        if (messages.size() > 0) {
        	//log.debug("SSMS "+name+" Got message from store ");
            return (SubsystemMessage) messages.remove(0);
        } else {
            throw new MessageNotAvailableException();
        }
    }

    /**
     *
     *
     * @param messageId
     * @param implementor
     */
    public void registerMessage(int messageId, Class implementor) {
        registeredMessages.put(new Integer(messageId), implementor);
    }
    
    /**
     * @return The number of messages currently in the store.
     */
    public int size() {
    	return messages.size();
    }

    /**
     *
     *
     * @return
     */
    public OpenClosedState getState() {
        return state;
    }

    /**
     *
     */
    public synchronized void close() {
        state.setValue(OpenClosedState.CLOSED);
        notifyAll();
    }
}
