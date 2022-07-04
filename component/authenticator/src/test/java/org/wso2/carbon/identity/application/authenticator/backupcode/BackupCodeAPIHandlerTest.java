package org.wso2.carbon.identity.application.authenticator.backupcode;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;

import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.HashMap;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_ENABLED_CLAIM;

@PrepareForTest({BackupCodeAPIHandler.class, BackupCodeUtil.class})
public class BackupCodeAPIHandlerTest extends PowerMockTestCase {

    private String username = "test1";
    private String tenantAwareUserName = "test1";

    @Mock
    MultitenantUtils multitenantUtils;

    @Mock
    UserRealm userRealm;

    @Mock
    UserStoreManager userStoreManager;

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    @Test(dataProvider = "backupCodesCountData")
    public void testGetRemainingBackupCodesCount(Map<String, String> userClaimValues, int remainingBackupCodesCount)
            throws UserStoreException, BackupCodeException {

        mockStatic(BackupCodeUtil.class);
        BackupCodeAPIHandler backupCodeAPIHandler = new BackupCodeAPIHandler();

        when(BackupCodeUtil.getUserRealm(username)).thenReturn(userRealm);
        when(multitenantUtils.getTenantAwareUsername(username)).thenReturn(tenantAwareUserName);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(userStoreManager.getUserClaimValues(tenantAwareUserName, new String[]{BACKUP_CODES_CLAIM}, null)).
                thenReturn(userClaimValues);

        int result = backupCodeAPIHandler.getRemainingBackupCodesCount(username);
        assertEquals(result, remainingBackupCodesCount);

    }

    @DataProvider(name = "backupCodesCountData")
    public Object[][] data() {

        Map<String, String> testClaims1 = new HashMap<>();
        testClaims1.put(BACKUP_CODES_CLAIM, "");
        testClaims1.put(BACKUP_CODES_ENABLED_CLAIM, "true");

        Map<String, String> testClaims2 = new HashMap<>();
        testClaims2.put(BACKUP_CODES_CLAIM, "234563");
        testClaims2.put(BACKUP_CODES_ENABLED_CLAIM, "true");


        Map<String, String> testClaims3 = new HashMap<>();
        testClaims3.put(BACKUP_CODES_CLAIM, null);
        testClaims3.put(BACKUP_CODES_ENABLED_CLAIM, "true");

        Map<String, String> testClaims4 = new HashMap<>();
        testClaims4.put(BACKUP_CODES_CLAIM, "234563,467064");
        testClaims4.put(BACKUP_CODES_ENABLED_CLAIM, "true");

        return new Object[][]{
                {testClaims1, 0},
                {testClaims2, 1},
                {testClaims3, 0},
                {testClaims4, 2}
        };
    }

    public void testGenerateBackupCodes() {
    }

    public void testDeleteBackupCodes() {
    }
}