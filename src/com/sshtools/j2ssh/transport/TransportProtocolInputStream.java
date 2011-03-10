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
package com.sshtools.j2ssh.transport;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.net.SocketException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.sshtools.j2ssh.io.ByteArrayReader;
import com.sshtools.j2ssh.io.ByteArrayWriter;
import com.sshtools.j2ssh.transport.cipher.SshCipher;
import com.sshtools.j2ssh.transport.compression.SshCompression;
import com.sshtools.j2ssh.transport.hmac.SshHmac;

/**
 * This class is responsible for reading bytes from the Socket stream,
 * decrypting and decompressing the bytes as necessary, and then returning
 * the decrypted message. The readMessage() method does all this, waiting
 * until the bytes for a whole message are available.
 */
class TransportProtocolInputStream {
    private static Log log = LogFactory.getLog(TransportProtocolInputStream.class);
    private static final int DEFAULT_CIPHER_LENGTH = 8;
	private static final int MAX_BUFFER_SIZE = 2 * 1024 * 1024; // 2meg
    private long bytesTransfered = 0;
    private final InputStream in;
    private Object sequenceLock = new Object();
    private TransportProtocolCommon transport;
    private TransportProtocolAlgorithmSync algorithms;
    private long sequenceNo = 0;
    private long sequenceWrapLimit = BigInteger.valueOf(2).pow(32).longValue();
    private SshCipher cipher;
    private SshHmac hmac;
    private SshCompression compression;
    private int msglen;
    private int padlen;
    private int read;
    private int remaining;
    private int cipherlen = DEFAULT_CIPHER_LENGTH;
    private int maclen = 0;

    private ByteArrayWriter messageBytes = new ByteArrayWriter();
    private byte[] initial = new byte[cipherlen];
    private byte[] data = new byte[65535];
    private byte[] buffered = new byte[65535];
    private int startpos = 0;
    private int endpos = 0;

    /**
     * Creates a new TransportProtocolInputStream object.
     *
     * @param transport
     * @param in
     * @param algorithms
     *
     * @throws IOException
     */
    public TransportProtocolInputStream(TransportProtocolCommon transport,
    			final InputStream in, TransportProtocolAlgorithmSync algorithms)
        throws IOException {
        this.transport = transport;
        this.in = new BufferedInputStream(in);
        //this.in = in;
        this.algorithms = algorithms;
    }
    
    
    private void logInfo() {
		/**
		 * Log what's in the buffer. We want to see if there's data stuck. If it is
		 * then we'd see blocking=true with readLoops>1, indicating it had read in some
		 * data and now was waiting. In this case some data would be stuck.
		 */
    }

    /**
     * Every message has a sequence number, which is incremented by 1 each time.
     * The value returned here is the number that will be assigned to the next
     * message.
     */
    public synchronized long getSequenceNo() {
        return sequenceNo;
    }

    /**
     *
     *
     * @return
     */
    protected long getNumBytesTransfered() {
        return bytesTransfered;
    }

    /**
     *
     *
     * @return
     */
    protected int available() {
        return endpos - startpos;
    }

    /**
     * Grab raw encrypted bytes from the socket. Will block until
     * it has len bytes and places them into buf.
     */
    protected int readBufferedData(byte[] buf, int off, int len)
        throws IOException {
    	
        int read;

        //if we don't already have enough data...
        if ((endpos - startpos) < len) {
            // Double check the buffer has enough room for the data
        	
            if ((buffered.length - endpos) < len) {
                // no it does not odds are that the startpos is too high
            	if (log.isDebugEnabled()) log.debug("Shifting buffer contents to start");
                System.arraycopy(buffered, startpos, buffered, 0,
                    endpos - startpos);
                endpos -= startpos;
                startpos = 0;

                if ((buffered.length - endpos) < len) {
                    log.debug("Resizing message buffer");
                    // Last resort resize the buffer to the required length
                    // this should stop any chance of error
                    byte[] tmp = new byte[buffered.length + len];
                    System.arraycopy(buffered, 0, tmp, 0, endpos);
                    buffered = tmp;
                }
            }

                   
            // If there is not enough data then block and read until there is (if still connected)
            while (((endpos - startpos) < len) &&
                    (transport.getState().getValue() != TransportProtocolState.DISCONNECTED)) {
                try {
                    read = in.read(buffered, endpos, (buffered.length - endpos));
                } catch (InterruptedIOException ex) { 
                    // We have an interrupted io; inform the event handler
                	log.warn("Interrupted IO");
                    read = ex.bytesTransferred;
                    for (TransportProtocolEventHandler eventHandler : transport.getEventHandlers()) {
                        eventHandler.onSocketTimeout(transport);
                    }
                }

                int bytesRead = read;
                if (read < 0) {
                	throw new EOFException("No more data on socket");
                }
                endpos += bytesRead;
            }
        } else {
        	//log.info("[TPIS][endpos-startpos >= len]");
        }

        System.arraycopy(buffered, startpos, buf, off, len);

        startpos += len;

        // Try to reset the buffer
        if (startpos >= endpos) {
            endpos = 0;
            startpos = 0;
        }

        return len;
    }

    /**
     * Grabs enough raw bytes to make up a message, decrypts them,
     * and returns them as the decrypted bytes of a single message.
     */
    public byte[] readMessage() throws SocketException, IOException {
        // Reset the message for the next
        messageBytes.reset();
        
        // Read the first byte of this message (this is so we block
        // but we will determine the cipher length before reading all
        read = readBufferedData(initial, 0, cipherlen);

        cipher = algorithms.getCipher();

        hmac = algorithms.getHmac();

        compression = algorithms.getCompression();

        // If the cipher object has been set then make sure
        // we have the correct blocksize
        if (cipher != null) {
            cipherlen = cipher.getBlockSize();
        } else {
            cipherlen = DEFAULT_CIPHER_LENGTH;
        }

        // Verify we have enough buffer size for the inital block,
        // otherwise recreate "initial" so it's the right size
        if (initial.length != cipherlen) {
            // Create a temporary array for the new block size and copy
            byte[] tmp = new byte[cipherlen];
            System.arraycopy(initial, 0, tmp, 0, initial.length);
            // Now change the initial buffer to our new array
            initial = tmp;
        }

        // Now read the rest of the first block of data if necessary
        int count = read;

        if (count < initial.length) {
            count += readBufferedData(initial, count, initial.length - count);
        }
        

        // Record the mac length
        if (hmac != null) {
            maclen = hmac.getMacLength();
        } else {
            maclen = 0;
        }

        // Decrypt the data if we have a valid cipher
        if (cipher != null) {
            initial = cipher.transform(initial);
        }

        // Save the initial data
        messageBytes.write(initial);

        // Preview the message length
        msglen = (int) ByteArrayReader.readInt(initial, 0);

        if (log.isDebugEnabled()) log.debug("Start of message of length " + msglen);
        
        padlen = initial[4];

        // Read, decrypt and save the remaining data
        remaining = (msglen - (cipherlen - 4));

        while (remaining > 0) {
        	if (log.isDebugEnabled()) log.debug("Reading rest of message, bytes left: " + remaining);
        	
            read = readBufferedData(data, 0,
                    (remaining < data.length)
                    ? ((remaining / cipherlen) * cipherlen)
                    : ((data.length / cipherlen) * cipherlen));
            remaining -= read;

            // Decrypt the data and/or write it to the message
            messageBytes.write((cipher == null) ? data
                                           : cipher.transform(data, 0, read),
                0, read);
        }
        if (log.isDebugEnabled()) log.debug("Finished reading message");
    
        if (messageBytes.size() > MAX_BUFFER_SIZE) {
        	throw new IOException("Message buffer grew too large: " + messageBytes.size());
        }

        synchronized (sequenceLock) {
            if (hmac != null) {
                read = readBufferedData(data, 0, maclen);

                messageBytes.write(data, 0, read);
                
                //log.info("TransportProtocolInputStream messageBytqes = " + messageBytes.size());

                // Verify the mac
                if (!hmac.verify(sequenceNo, messageBytes.toByteArray())) {
                    throw new IOException("Corrupt Mac on input");
                }
            }

            // Increment the sequence no
            if (sequenceNo < sequenceWrapLimit) {
                sequenceNo++;
            } else {
                sequenceNo = 0;
            }
        }

        bytesTransfered += messageBytes.size();

        byte[] msg = messageBytes.toByteArray();

        // Uncompress the message payload if necessary
        if (compression != null) {
            return compression.uncompress(msg, 5, (msglen + 4) - padlen - 5);
        }

        return msg;
    }
}
