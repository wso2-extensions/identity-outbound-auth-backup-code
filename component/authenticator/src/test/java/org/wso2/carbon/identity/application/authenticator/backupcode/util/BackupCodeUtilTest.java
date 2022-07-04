package org.wso2.carbon.identity.application.authenticator.backupcode.util;

import junit.framework.TestCase;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;

import java.util.List;

import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_LENGTH;

@PrepareForTest({BackupCodeUtil.class, BackupCodeDataHolder.class})
public class BackupCodeUtilTest extends TestCase {

    private String tenantDomain = "test.domain";

    @Mock
    IdentityGovernanceService identityGovernanceService;

    @Test
    public void testGenerateBackupCodes() throws BackupCodeException {

        BackupCodeUtil backupCodeUtil = new BackupCodeUtil();
        List<String> backupCodes = BackupCodeUtil.generateBackupCodes(tenantDomain);
    }

    @Test
    public void testGetAuthenticatedUser() {
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
    public void testEncrypt() {
    }

    @Test
    public void testDecrypt() {
    }

    @Test
    public void testGetBackupCodeAuthenticatorConfig() throws BackupCodeException {

        BackupCodeUtil backupCodeUtil = mock(BackupCodeUtil.class);
        BackupCodeDataHolder backupCodeDataHolder = new BackupCodeDataHolder();
        backupCodeDataHolder.setIdentityGovernanceService(identityGovernanceService);
        assertEquals(anyString(), backupCodeUtil.getBackupCodeAuthenticatorConfig("test", tenantDomain));
    }

    @Test(dataProvider = "hashStringData")
    public void testGenerateHashString(String backupCode) throws BackupCodeException {

        BackupCodeUtil backupCodeUtil = new BackupCodeUtil();
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
}