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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * A sliding window that represents how much data a computer is willing to receive.
 * The application will have two window objects per channel.
 * 
 * The local window represents how much data we are willing to receive. As we
 * receive data the window shrinks. When we think the window is too small, we increase it
 * and send a channel window adjust message to the other computer to let it know
 * how much we're growing it by.
 * 
 * The remote window represents the other host's local window. As we send them channel
 * data the remote window shrinks. If it gets to 0 we don't send any more data to them
 * until they send us a channel window adjust message. This ensures that we don't send
 * more data than the client can handle.
 * 
 * So in reality there are only two windows, but each host keeps track of both. Problems
 * can occur if one host's local window gets out of sync with the other host's
 * remote window, as they are supposed to be the same. It can lead to deadlocks and
 * disconnections.
 */
public class ChannelDataWindow {
    private static Log log = LogFactory.getLog(ChannelDataWindow.class);
    long windowSpace = 0;
    
    String name;
    
    private boolean actuallyWait = true;

    /**
     * Creates a new ChannelDataWindow object.
     * name is used to identify it in logs.
     */
    public ChannelDataWindow(String name) {
    	this.name = name;
    }
    
    /**
     * Create a data window, specifying what to do when all the
     * window space is consume. If waitForSpace is false, it will
     * allow the size of the window to drop below zero - it will
     * simply carry on rather than block.
     */
    public ChannelDataWindow(String name, boolean waitForSpace) {
    	this(name);
    	actuallyWait = waitForSpace;
    }

    /**
     *
     *
     * @return
     */
    public synchronized long getWindowSpace() {
        return windowSpace;
    }

    /**
     *
     *
     * @param count
     *
     * @return
     */
    public synchronized long consumeWindowSpace(int count) {
//        if (windowSpace < count) {
//        	if (actuallyWait) {
//        		waitForWindowSpace(count);
//        	} else {
//        		if (log.isInfoEnabled()) {
//	        		log.info(name+": NOT waiting for " + String.valueOf(count) +
//	                        " bytes of window space");
//        		}
//        	}
//        }

        windowSpace -= count;

        return windowSpace;
    }

    /**
     *
     *
     * @param count
     */
    public synchronized void increaseWindowSpace(long count) {
        if (log.isDebugEnabled()) {
            log.debug(name+": Increasing window space by " + String.valueOf(count));
        }

        windowSpace += count;
        notifyAll();
    }

    /**
     *
     *
     * @param minimum
     */
    public synchronized void waitForWindowSpace(int minimum, int count) {
        if (log.isDebugEnabled() && windowSpace < minimum) {
            log.debug(name+": Waiting for " + String.valueOf(minimum) +
                " bytes of window space : " + count + " + times.");
        }

        int currentCount = 0;
        while (windowSpace < minimum && currentCount < count) {
            try {
                currentCount ++;
                wait(50);
            } catch (InterruptedException e) {
            }
        }
    }
}
