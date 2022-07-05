package org.wso2.carbon.identity.application.authenticator.backupcode.util;

import junit.framework.TestCase;
import org.mockito.Mock;
import org.mockito.Spy;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.AssertJUnit.assertEquals;

@PrepareForTest({BackupCodeUtil.class, BackupCodeDataHolder.class, MultitenantUtils.class, IdentityTenantUtil.class})
public class BackupCodeUtilTest extends PowerMockTestCase {

    private String username = "test1";
    private String tenantDomain = "test.domain";
    private int tenantId = -1234;

    BackupCodeUtil backupCodeUtil = new BackupCodeUtil();

    @Mock
    RealmService realmService;

    @Mock
    UserRealm userRealm;

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

        AuthenticationContext authenticationContext = new AuthenticationContext();
        SequenceConfig sequenceConfig = new SequenceConfig();
        authenticationContext.setSequenceConfig(sequenceConfig);
        AuthenticatedUser authenticatedUser = backupCodeUtil.getAuthenticatedUser(authenticationContext);
        assertEquals(null, authenticatedUser);
    }

    @Test
    public void testGetRealmService() {


    }

    @Test
    public void testGetUserRealm() throws UserStoreException {
        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(BackupCodeDataHolder.class);
        when(MultitenantUtils.getTenantDomain(username)).thenReturn(tenantDomain);
        when(IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(tenantId);
        when(BackupCodeDataHolder.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantUserRealm(tenantId)).thenReturn(userRealm);
        assertEquals(userRealm, backupCodeUtil.getUserRealm(username));
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