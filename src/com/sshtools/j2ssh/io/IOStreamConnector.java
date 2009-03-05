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
package com.sshtools.j2ssh.io;

import com.sshtools.j2ssh.*;

import org.apache.commons.logging.*;

import java.io.*;

import javax.swing.event.*;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.29 $
 */
public class IOStreamConnector {
    private static Log log = LogFactory.getLog(IOStreamConnector.class);
    private IOStreamConnectorState state = new IOStreamConnectorState();
    private InputStream in = null;
    private OutputStream out = null;
    private Thread thread;
    private long bytes;
    private boolean closeInput = true;
    private boolean closeOutput = true;

    /**  */
    protected EventListenerList listenerList = new EventListenerList();

    /**
     * Creates a new IOStreamConnector object.
     */
    public IOStreamConnector() {
    }

    /**
     * Creates a new IOStreamConnector object.
     *
     * @param in
     * @param out
     */
    public IOStreamConnector(InputStream in, OutputStream out) {
        connect(in, out);
    }

    public IOStreamConnectorState getState() {
        return state;
    }

    public void close() throws IOException {
        log.info("Closing IOStreamConnector");
        state.setValue(IOStreamConnectorState.CLOSED);

        if (closeInput) {
            in.close();
        }

        if (closeOutput) {
            out.close();
        }
        
        //Interrupt waiting message loops so they notice everyone's going home
        if (thread != null) {
        	thread.interrupt();
        }

        thread = null;
    }

    public void setCloseInput(boolean closeInput) {
        this.closeInput = closeInput;
    }


    public void setCloseOutput(boolean closeOutput) {
        this.closeOutput = closeOutput;
    }

    public void connect(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
        log.info("Connecting InputStream to OutputStream");
        state.setValue(IOStreamConnectorState.CONNECTED);
        thread = new SshThread(new IOStreamConnectorThread(),
                "IOStream connector", true);
        thread.start();
    }

    public long getBytes() {
        return bytes;
    }

    public void addIOStreamConnectorListener(IOStreamConnectorListener l) {
        listenerList.add(IOStreamConnectorListener.class, l);
    }

    public void removeIOStreamConnectorListener(IOStreamConnectorListener l) {
        listenerList.remove(IOStreamConnectorListener.class, l);
    }

    class IOStreamConnectorThread implements Runnable {
        private Log log = LogFactory.getLog(IOStreamConnectorThread.class);
        
        public void run() {
        	try {
	            byte[] buffer = new byte[4096];
	            int read = 0;
	            int count;
	            int available;
	            log.info("Starting IOStreamConnectorThread thread");
	
	            while (state.getValue() == IOStreamConnectorState.CONNECTED) {
	                try {
	                    // Block
	                    read = in.read(buffer, 0, 1);
	
	                    if (read > 0) {
	                        count = read;
	                        available = in.available();
	
	                        // Verify the buffer length and adjust if necersary
	                        if ((available > 0) &&
	                                ((buffer.length - 1) < available)) {
	                            byte[] tmp = new byte[available + 1];
	                            System.arraycopy(buffer, 0, tmp, 0, 1);
	                            buffer = tmp;
	                        }
	
	                        // Read the remaining available bytes of the message
	                        if (available > 0) {
	                            read = in.read(buffer, 1, available);
	                            count += read;
	                        }
	
	                        // Write the message to the output stream
	                        out.write(buffer, 0, count);
	                        bytes += count;
	
	                        // Flush it
	                        out.flush();
	                        
	                        IOStreamConnectorListener[] l = (IOStreamConnectorListener[]) listenerList.getListeners(IOStreamConnectorListener.class);
	                        for (int i = (l.length - 1); i >= 0; i--) {
	                            l[i].data(buffer, read);
	                        }
	                    } else {
	                        log.debug("Blocking read returned with " +
	                            String.valueOf(read));
	
	                        if (read < 0) {
	                            state.setValue(IOStreamConnectorState.EOF);
	                        }
	                    }
	                } catch (IOException ioe) {
	                    // only warn if we're supposed to be still connected, as we will ignore close exceptions
	                    if (state.getValue() == IOStreamConnectorState.CONNECTED) {
	                        log.debug(ioe.getMessage());
	                        state.setValue(IOStreamConnectorState.EOF);
	                    }
	                }
	            }
	
	            try {
	                // if we're not already closed then close the connector
	                if (state.getValue() != IOStreamConnectorState.CLOSED) {
	                    close();
	                }
	            } catch (IOException ioe) {
	            }
	
	            log.info("IOStreamConnectorThread is exiting");
        	} catch (RuntimeException e) {
        		log.fatal(e);
        		throw e;
        	}
        }
    }
}
