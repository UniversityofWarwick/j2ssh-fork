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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import com.sshtools.j2ssh.StaticBytePool;


/**
 *
 *
 * @author $author$
 * @version $Revision: 1.16 $
 */
public class ByteArrayReader extends ByteArrayInputStream {
    public static final String UTF_8 = "UTF8";

	/**
     * Creates a new ByteArrayReader object.
     *
     * @param data
     */
    public ByteArrayReader(byte[] data) {
        super(data);
    }

    /**
     *
     *
     * @param data
     * @param start
     *
     * @return
     */
    public static long readInt(byte[] data, int start) {
        long ret = (((long) (data[start] & 0xFF) << 24) & 0xFFFFFFFF) |
            ((data[start + 1] & 0xFF) << 16) | ((data[start + 2] & 0xFF) << 8) |
            ((data[start + 3] & 0xFF) << 0);

        return ret;
    }

    /**
     *
     *
     * @return
     *
     * @throws IOException
     */
    public long readInt() throws IOException {
        byte[] raw = new byte[4];
        read(raw);

        long ret = (((long) (raw[0] & 0xFF) << 24) & 0xFFFFFFFF) |
            ((raw[1] & 0xFF) << 16) | ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);

        return ret;
    }

    /**
     *
     *
     * @return
     *
     * @throws IOException
     */
    public UnsignedInteger32 readUINT32() throws IOException {
        return new UnsignedInteger32(readInt());
    }

    /**
     *
     *
     * @return
     *
     * @throws IOException
     */
    public UnsignedInteger64 readUINT64() throws IOException {
        byte[] raw = new byte[8];
        read(raw);

        return new UnsignedInteger64(raw);
    }

    /**
     *
     *
     * @param data
     * @param start
     *
     * @return
     */
    public static String readString(byte[] data, int start) {
        int len = (int)readInt(data, start);
        if (len < 0) {
			throw new IllegalArgumentException("Invalid data, had a negative length");
		} else if (start + len > data.length) {
			throw new IllegalArgumentException("Invalid data, length greater than available data");
		}
        byte[] chars = new byte[len];
        System.arraycopy(data, start + 4, chars, 0, len);
        try {
			return new String(chars, UTF_8);
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Can't find UTF-8 encoding!!", e);
		}
    }

    /**
     *
     *
     * @return
     *
     * @throws IOException
     */
    public BigInteger readBigInteger() throws IOException {
        int len = (int)readInt();
        verifyLength(len);
        byte[] raw = new byte[len];
        read(raw);

        return new BigInteger(raw);
    }

    public byte[] readBinaryString() throws IOException {
        int len = (int)readInt();
        verifyLength(len);
        byte[] raw = new byte[len];
        read(raw);
        return raw;
    }
    
    /**
     * Read a string into an array
     */
    public byte[] readBinaryStringPooled() throws IOException {
        int len = (int)readInt();
        if (len == -1) {
        	len = 0; // KDE sends -1 sometimes. I don't know why.
        } else {
        	verifyLength(len);
        }
        byte[] raw = StaticBytePool.get(len);
        read(raw);
        return raw;
    }

   
    public String readString() throws IOException {
        int len = (int)readInt();
        verifyLength(len);
        
        byte[] raw = new byte[len];
        read(raw);

        return new String(raw, UTF_8);
    }
    
    /**
     * Ensure that the bytes read as length are valid, by checking it is
     * a positive number and that it's less than or equal to the actual amount
     * of data available.
     */
    private final void verifyLength(final int len) throws IOException {
		if (len < 0) {
			// The client is sending nonsense.
			throw new IOException("Invalid data, had a negative length");
		} else if (len > available()) {
			throw new IOException("Invalid data, length greater than available data");
		}
	}
}
