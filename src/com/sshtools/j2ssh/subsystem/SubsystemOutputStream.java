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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.j2ssh.io.ByteArrayReader;
import com.sshtools.j2ssh.transport.InvalidMessageException;


/**
 * The SubsystemOutputStream is actually used to process
 * incoming messages. The SSH server will write incoming
 * bytes to it, which it will send off to the contained
 * SubsystemMessageStore as new messages. Thus, this object
 * would be given the store for incoming messages.
 */
public class SubsystemOutputStream extends OutputStream {
	
	/**
	 * The number of bytes at the start of a message, which contain
	 * an unsigned 32-bit integer indicating the length of the
	 * _rest_ of the message.
	 */
	private static final int LENGTH_BYTES = 4;

	private static final Log LOG = LogFactory.getLog(SubsystemOutputStream.class);
	
	private static final int MAX_BUFFER_SIZE = 2*1024*1024; //2meg
	private static final int FORCE_RESET_SIZE = 1*1024*1024; //1meg
	
    // Temporary storage buffer to build up a message
	private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
	// Where in the buffer does the current message start
	private int messageStart = 0;
	
	private SubsystemMessageStore messageStore;
    
    /**
     * Creates a new SubsystemOutputStream object.
     *
     * @param messageStore
     */
    public SubsystemOutputStream(SubsystemMessageStore messageStore) {
        super();
        this.messageStore = messageStore;
    }



    /**
     *
     *
     * @param b
     * @param off
     * @param len
     *
     * @throws IOException
     */
    public void write(byte[] b, int off, int len) throws IOException {
        // Write the data
    	//LOG.debug(String.format("[SSOS]write(byte[%d],%d,%d", b.length, off, len));
        super.write(b, off, len);        
        processMessage();
    }
    
    @Override
    public void close() throws IOException {
    	try {
    		LOG.debug("Closing subsystem output stream");
    		processMessage();
    	} finally {
    		super.close();
    	}
    }

    /**
     *
     *
     * @param b
     *
     * @throws IOException
     */
    public void write(int b) throws IOException {
        buffer.write(b);
    }

    private void processMessage() throws IOException {
    	synchronized(buffer) {
	        // Now try to process a message
    		if (buffer.size() > MAX_BUFFER_SIZE) {
    			// Buffer should never grow this big.
    			throw new IOException("Buffer grew too large: " + buffer.size());
    		}
    		
	        if (buffer.size() > (messageStart + LENGTH_BYTES)) {
	        	
	        	//Messagelength is the length of data AFTER the 4 bytes containing the length.
	            byte[] byteArray = buffer.toByteArray();
				int messageLength = (int) ByteArrayReader.readInt(byteArray, messageStart);
	            //int messageType = buffer.toByteArray()[messageStart + LENGTH_BYTES];
	            
	            if (messageLength + messageStart <= (buffer.size() - LENGTH_BYTES)) {
	            	
	                byte[] msgdata = new byte[messageLength];
	                
	                // Process a message
	                System.arraycopy(byteArray, messageStart + LENGTH_BYTES,
	                    msgdata, 0, messageLength);
	
	                try {
	                    messageStore.addMessage(msgdata);
	                } catch (InvalidMessageException ime) {
	                    throw new IOException(
	                        "An invalid message was encountered in the outputstream: " +
	                        ime.getMessage());
	                }
	
	                if (messageStart + LENGTH_BYTES + messageLength == (buffer.size())) {
	                	//Message reached the exact end of the buffer, so reset it
	                	if (LOG.isDebugEnabled()) LOG.debug("Reset buffer");
	                    buffer.reset();
	                    messageStart = 0;
	                } else {
	                	int remaining = buffer.size() - (LENGTH_BYTES + messageLength + messageStart);
	                    messageStart += messageLength + LENGTH_BYTES;
	                    
	                    if (messageStart > FORCE_RESET_SIZE) {
	                    	if (LOG.isDebugEnabled()) LOG.debug("Shifting large buffer back to start. messageStart=" + messageStart);
	                    	buffer.reset();
	                    	buffer.write(byteArray, messageStart, remaining);
	                    	messageStart = 0;
	                    } else {
		                    if (LOG.isDebugEnabled()) LOG.debug("Start buffer at " + messageStart);
		                    //write() may not get called again, so
		                    //we need to check whether these extra bytes are a whole
		                    //message. Otherwise it will be stuck in buffer limbo.
	                    }
	                    processMessage();
	                }
	            } else {
	            	if (LOG.isDebugEnabled()) {
	            		LOG.debug("Incomplete message: "+messageLength+", messageStart:"+messageStart+", buffer:"+(buffer.size() - LENGTH_BYTES));
	            	}
	            }
	        } else {
	        	if (LOG.isDebugEnabled()) {
	        		LOG.debug("Haven't received the message length yet");
	        	}
	        }
    	}
    }
}
