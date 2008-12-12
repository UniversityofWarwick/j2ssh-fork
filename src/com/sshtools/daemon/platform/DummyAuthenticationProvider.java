package com.sshtools.daemon.platform;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * This authentication provider provides no authentication at all,
 * and just lets anybody in so you should never use it! 
 * 
 * It is really just for testing.
 */
public class DummyAuthenticationProvider extends NativeAuthenticationProvider {

	Log log = LogFactory.getLog(DummyAuthenticationProvider.class);
	
	public DummyAuthenticationProvider() {
		log.error("DummyAuthenticationProvider is in use. This is only for testing.");
	}
	
	@Override
	public boolean changePassword(String username, String oldpassword,
			String newpassword) {
		return false;
	}

	@Override
	public String getHomeDirectory(String username) throws IOException {
		return "/home/" + username;
	}

	@Override
	public void logoffUser() throws IOException {
		
	}

	@Override
	public boolean logonUser(String username, String password)
			throws PasswordChangeException, IOException {
		return true;
	}

	@Override
	public boolean logonUser(String username) throws IOException {
		return true;
	}

}
