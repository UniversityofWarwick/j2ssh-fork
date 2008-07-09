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
package com.sshtools.j2ssh.sftp;

import com.sshtools.j2ssh.io.ByteArrayReader;
import com.sshtools.j2ssh.io.ByteArrayWriter;
import com.sshtools.j2ssh.io.UnsignedInteger32;
import com.sshtools.j2ssh.subsystem.SubsystemMessage;
import com.sshtools.j2ssh.transport.InvalidMessageException;

import java.io.IOException;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


/**
 * Message sent in response to SshFxpInit. The init
 * from the client contains a suggested protocol version;
 * the version in this message is the version that the
 * server decides both ends can understand.
 */
public class SshFxpVersion extends SubsystemMessage {
    /** The ID of this message type. */
    public static final int SSH_FXP_VERSION = 2;
    private UnsignedInteger32 version;
    private Map extended = null;

    /**
     * Creates a new SshFxpVersion object.
     */
    public SshFxpVersion() {
        super(SSH_FXP_VERSION);
    }

    /**
     * Creates a new SshFxpVersion object.
     *
     * @param version
     * @param extended
     */
    public SshFxpVersion(UnsignedInteger32 version, Map extended) {
        super(SSH_FXP_VERSION);
        this.version = version;
        this.extended = extended;
    }


    public UnsignedInteger32 getVersion() {
        return version;
    }


    public Map getExtended() {
        return extended;
    }


    public void constructMessage(ByteArrayReader bar)
        throws IOException, InvalidMessageException {
        version = bar.readUINT32();
        extended = new HashMap();

        String key;
        String value;

        while (bar.available() > 0) {
            key = bar.readString();
            value = bar.readString();
            extended.put(key, value);
        }
    }


    public String getMessageName() {
        return "SSH_FXP_INIT";
    }


    public void constructByteArray(ByteArrayWriter baw)
        throws IOException, InvalidMessageException {
        baw.writeUINT32(version);

        if (extended != null) {
            if (extended.size() > 0) {
                Iterator it = extended.entrySet().iterator();
                Map.Entry entry;

                while (it.hasNext()) {
                    entry = (Map.Entry) it.next();
                    baw.writeString((String) entry.getKey());
                    baw.writeString((String) entry.getValue());
                }
            }
        }
    }
}
