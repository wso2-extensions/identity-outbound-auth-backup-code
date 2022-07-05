package org.wso2.carbon.identity.application.authenticator.backupcode.util;

import junit.framework.TestCase;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;

@PrepareForTest({BackupCodeUtil.class, BackupCodeDataHolder.class})
public class BackupCodeUtilTest extends TestCase {

    BackupCodeUtil backupCodeUtil = new BackupCodeUtil();

    @Spy
    AuthenticationContext authenticationContext;

    @Test(dataProvider = "hashStringData")
    public void testGenerateHashString(String backupCode) throws BackupCodeException {

        String hashedCode = backupCodeUtil.generateHashString(backupCode);
        String duplicatedHashedCode = backupCodeUtil.generateHashString(backupCode);
        assertEquals(hashedCode, duplicatedHashedCode);
    }

    @DataProvider(name = "hashStringData")
    public Object[][] hashStringData(){

        return new Object[][] {
                {" "},
                {""},
                {"234563"},
                {"!@#(*"},
                {null}
        };
    }

    @Test
    public void testGetAuthenticatedUser() {
        AuthenticationContext authenticationContext1 = new AuthenticationContext();
        SequenceConfig sequenceConfig = new SequenceConfig();
        authenticationContext1.setSequenceConfig(sequenceConfig);
        AuthenticatedUser authenticatedUser = backupCodeUtil.getAuthenticatedUser(authenticationContext1);
        assertEquals(null, authenticatedUser);
    }

    @Test
    public void testGetRealmService() {
    }

    @Test
    public void testGetUserRealm() {
    }

    @Test
    public void testGetMultiOptionURIQueryParam() {
    }

    @Test
    public void testGetBackupCodeLoginPage() {
    }

    @Test
    public void testGetLoginPageFromXMLFile() {
    }

    @Test
    public void testGetBackupCodeErrorPage() {
    }

    @Test
    public void testGetErrorPageFromXMLFile() {
    }

    @Test
    public void testIsLocalUser() {
    }

    @Test
    public void testIsAccountLocked() {
    }

    @Test
    public void testGenerateBackupCodes() {
    }

    @Test
    public void testGetBackupCodeAuthenticatorConfig() {
    }
}