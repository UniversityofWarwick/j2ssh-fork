package com.sshtools.j2ssh.sftp;

import java.io.IOException;

import com.sshtools.j2ssh.io.ByteArrayReader;
import com.sshtools.j2ssh.io.ByteArrayWriter;
import com.sshtools.j2ssh.io.UnsignedInteger32;
import com.sshtools.j2ssh.subsystem.SubsystemMessage;
import com.sshtools.j2ssh.transport.InvalidMessageException;

public class IncompleteMessage extends SubsystemMessage implements MessageRequestId {

	// There's no such message type in the SFTP protocol
	// so just make up a non-conflicting ID.
	public static final int FAKE_ID = 1010101;
	
	private UnsignedInteger32 id;
	
	public IncompleteMessage() {
		super(FAKE_ID);
	}

	@Override
	public void constructByteArray(ByteArrayWriter baw)
			throws InvalidMessageException, IOException {
		// TODO Auto-generated method stub

	}

	@Override
	public void constructMessage(ByteArrayReader bar)
			throws InvalidMessageException, IOException {
		id = bar.readUINT32();
		//don't care about any further data 
		//(indeed, we don't know what it is)
	}

	@Override
	public String getMessageName() {
		return "INTERNAL:INCOMPLETE_MESSAGE";
	}

	public UnsignedInteger32 getId() {
		return id;
	}

}
