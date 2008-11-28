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

import com.sshtools.j2ssh.io.ByteArrayReader;
import com.sshtools.j2ssh.sftp.IncompleteMessage;
import com.sshtools.j2ssh.transport.InvalidMessageException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Date;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


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
	
	private static final long AMOUNT_OF_TIME_TO_WAIT_FOR_SFTPDRIVE_TO_GET_ITS_SHIT_TOGETHER = 1000;

	private static final Log LOG = LogFactory.getLog(SubsystemOutputStream.class);
	
    // Temporary storage buffer to build up a message
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    SubsystemMessageStore messageStore;
    int messageStart = 0;
    
    long lastChunkReceived;

    
    /**
     * Creates a new SubsystemOutputStream object.
     *
     * @param messageStore
     */
    public SubsystemOutputStream(SubsystemMessageStore messageStore) {
        super();
        this.messageStore = messageStore;
        
        /*
         * This is some testing code to log a status message every 2 seconds,
         * so I can keep an eye on the state of the stream buffer. 
         */
//        t = new Timer("SubsystemOutputStream");
//        t.scheduleAtFixedRate(new TimerTask(){
//			@Override
//			public void run() {
//				//LOG.info("I am going to write you a story");
//				int messageLength = -1;
//				int messageType = -1;
//				if (buffer.size() > messageStart + 5 ) {
//					messageLength = (int) ByteArrayReader.readInt(buffer.toByteArray(), messageStart);
//					messageType = buffer.toByteArray()[messageStart + LENGTH_BYTES];
//				}
//				LOG.info(String.format("[SSOS][%d][buffer=%d][messageStart=%d][messageLength=%d][messageType=%d]", hashCode(), buffer.size(), messageStart, messageLength, messageType));
//				
//				if (System.currentTimeMillis() > lastChunkReceived + AMOUNT_OF_TIME_TO_WAIT_FOR_SFTPDRIVE_TO_GET_ITS_SHIT_TOGETHER) {
//					if (messageStart < buffer.size()) {
//						//stuck with part of a message. what is going on?
//						LOG.warn("Stuck with half a message");
////						try {
////							processIncompleteMessage();
////						} catch (IOException e) {
////							// TODO Auto-generated catch block
////							LOG.error("Error trying to package up IncompleteMessage", e);
////						}
//					}
//				}
//			}
//
//		}, new Date(), 2000);
        
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
	    	lastChunkReceived = System.currentTimeMillis();
	        // Now try to process a message
	        if (buffer.size() > (messageStart + LENGTH_BYTES)) {
	        	//Messagelength is the length of data AFTER the 4 bytes containing the length.
	            int messageLength = (int) ByteArrayReader.readInt(buffer.toByteArray(),
	                    messageStart);
	            int messageType = buffer.toByteArray()[messageStart + LENGTH_BYTES];
	            
	            //oh dear... what's this
	            // HACK HACK HACK HACK
	            boolean writeHack = false && messageType == 6 && messageStart == 0;
	            
	            if (writeHack || messageLength + messageStart <= (buffer.size() - LENGTH_BYTES)) {
	            	//LOG.debug("COMPLETED Message: "+messageLength+", messageStart:"+messageStart+", buffer:"+(buffer.size() - LENGTH_BYTES));
	            	// HACK HACK HACK HACK
	                if (writeHack) {
	                    // HACK HACK HACK HACK
	                	messageLength = buffer.size() - LENGTH_BYTES;  // HACK HACK HACK HACK
	                	//LOG.info()
	                }
	            	
	                byte[] msgdata = new byte[messageLength];
	
	                // HACK HACK HACK HACK
	                
	                // Process a message
	                System.arraycopy(buffer.toByteArray(), messageStart + LENGTH_BYTES,
	                    msgdata, 0, messageLength);
	
	                try {
	                    messageStore.addMessage(msgdata);
	                } catch (InvalidMessageException ime) {
	                    throw new IOException(
	                        "An invalid message was encountered in the outputstream: " +
	                        ime.getMessage());
	                }
	
	                if (messageLength + messageStart == (buffer.size() - LENGTH_BYTES)) {
	                    buffer.reset();
	                    messageStart = 0;
	                } else {
	                	int remaining = buffer.size() - (LENGTH_BYTES + messageLength + messageStart);
	                    messageStart += messageLength + LENGTH_BYTES;
	                    //write() may not get called again, so
	                    //we need to check whether these extra bytes are a whole
	                    //message. Otherwise it will be stuck in buffer limbo.
	                    processMessage();
	                }
	            } else {
	            	//LOG.debug("Incomplete message: "+messageLength+", messageStart:"+messageStart+", buffer:"+(buffer.size() - LENGTH_BYTES));
	            }
	        } else {
	        	//LOG.debug("Haven't received the message length yet");
	        }
    	}
    }
    
    // HACK HACK HACK HACK
	private void processIncompleteMessage() throws IOException {
		synchronized(buffer) {
			//Do this check again, just in case it locks and a message comes in to
			//fix it. Incredibly unlikely but hey
			if (System.currentTimeMillis() > lastChunkReceived + AMOUNT_OF_TIME_TO_WAIT_FOR_SFTPDRIVE_TO_GET_ITS_SHIT_TOGETHER) {
				LOG.warn("Generating an IncompleteMessage as we have data stuck in the buffer");
				int messageLength = buffer.size() - (LENGTH_BYTES + messageStart);  // HACK HACK HACK HACK
		        byte[] msgdata = new byte[messageLength];
		        
		        // Process a message
		        System.arraycopy(buffer.toByteArray(), messageStart + LENGTH_BYTES,
		            msgdata, 0, messageLength);
				
				IncompleteMessage message = new IncompleteMessage();
				message.fromByteArray(msgdata);
				messageStore.addMessage(message);
				
				buffer.reset();
				messageStart = 0;
			}
		}
	}
}
