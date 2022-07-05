package org.wso2.carbon.identity.application.authenticator.backupcode;

import junit.framework.TestCase;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.Test;

@PrepareForTest({BackupCodeAuthenticator.class})
public class BackupCodeAuthenticatorTest extends TestCase {

    public void testProcess() {
    }

    public void testCanHandle() {
    }

    public void testRetryAuthenticationEnabled() {
    }

    public void testGetContextIdentifier() {
    }

    @Test
    public void testTestGetName() {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        assertEquals(  "backup-code-authenticator", backupCodeAuthenticator.getName());
    }

    @Test
    public void testGetFriendlyName() {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        assertEquals(  "Backup Code Authenticator", backupCodeAuthenticator.getFriendlyName());
    }

    public void testInitiateAuthenticationRequest() {
    }

    public void testProcessAuthenticationResponse() {
    }
}
