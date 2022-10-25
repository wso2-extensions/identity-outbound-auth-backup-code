/*
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.org).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.backupcode;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.mockito.Mock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.api.support.membermodification.MemberMatcher;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.core.model.IdentityErrorMsgContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.support.membermodification.MemberModifier.suppress;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATION;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT;

@PrepareForTest({BackupCodeAuthenticator.class, BackupCodeUtil.class, BackupCodeDataHolder.class,
        FileBasedConfigurationBuilder.class, IdentityUtil.class,
        FederatedAuthenticatorUtil.class, IdentityCoreServiceComponent.class, CarbonUtils.class})
public class BackupCodeAuthenticatorTest extends PowerMockTestCase {

    @Mock
    HttpServletRequest mockHttpServletRequest;

    @Mock
    HttpServletResponse mocHttpServletResponse;

    @Mock
    AuthenticationContext mockAuthenticationContext;

    @Mock
    AuthenticatedUser mockAuthenticatedUser;

    @Mock
    UserStoreManager mockUserStoreManager;

    @Mock
    IdentityEventService mockIdentityEventService;

    @Mock
    IdpManager mockIdpManager;

    @Mock
    IdentityProvider mockIdentityProvider;

    @Mock
    JustInTimeProvisioningConfig mockJustInTimeProvisioningConfig;

    @Mock
    ConfigurationContextService mockConfigurationContextService;

    @Mock
    ConfigurationContext mockConfigurationContext;

    @Mock
    AxisConfiguration mockAxisConfiguration;

    @Mock
    FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    private static final String VALID_TOKEN = "234561";
    private static final String INVALID_TOKEN = "123456";
    private static final String FULL_QUALIFIED_USERNAME = "TEST-DOMAIN/test@gmail.com@carbon.super";
    private static final String HASHED_BACKUP_CODES =
            "2d578fa2a67a4e24933164a78752f9ea60cdbcbcb683637b582595e49d19a305,2dc0269fa54d269a87536810ec453cb095b4b92f45e63826a21dff1c2e76f169";
    private static final String TENANT_DOMAIN = "carbon.super";
    private String redirect;

    @Test(dataProvider = "canHandleData")
    public void testCanHandle(String backupCode, boolean expectedValue) {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        when(mockHttpServletRequest.getParameter("BackupCode")).thenReturn(backupCode);
        assertEquals(expectedValue, backupCodeAuthenticator.canHandle(mockHttpServletRequest));
    }

    @DataProvider(name = "canHandleData")
    public Object[][] dataForCanHandle() {

        return new Object[][]{{"123567", true}, {null, false}};
    }

    @Test
    public void testTestGetName() {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        assertEquals("backup-code-authenticator", backupCodeAuthenticator.getName());
    }

    @Test
    public void testGetFriendlyName() {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        assertEquals("Backup Code", backupCodeAuthenticator.getFriendlyName());
    }

    @Test(dataProvider = "processAuthenticationResponseData")
    public void testProcessAuthenticationResponse(String token, String fullyQualifiedUserName, boolean isLocalUser,
                                                  boolean isAccountLock, boolean isInitialFedAttempt,
                                                  Map<String, String> claims, boolean expectError)
            throws IdentityEventException, UserStoreException {

        mockStatic(BackupCodeUtil.class, CALLS_REAL_METHODS);
        mockStatic(BackupCodeDataHolder.class);
        when(mockHttpServletRequest.getParameter(BACKUP_CODE)).thenReturn(token);
        when(mockAuthenticationContext.getProperty(AUTHENTICATED_USER)).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.toFullQualifiedUsername()).thenReturn(fullyQualifiedUserName);
        try {
            PowerMockito.doReturn(isLocalUser).when(BackupCodeUtil.class, "isLocalUser", mockAuthenticationContext);
            PowerMockito.doReturn(isAccountLock)
                    .when(BackupCodeUtil.class, "isAccountLocked", anyString(), anyString(), anyString());
            PowerMockito.doReturn(mockUserStoreManager)
                    .when(BackupCodeUtil.class, "getUserStoreManagerOfUser", anyString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        when(BackupCodeDataHolder.getIdentityEventService()).thenReturn(mockIdentityEventService);
        doNothing().when(mockIdentityEventService).handleEvent(anyObject());
        when(mockAuthenticationContext.getProperty(IS_INITIAL_FEDERATED_USER_ATTEMPT)).thenReturn(isInitialFedAttempt);
        when(mockAuthenticationContext.getProperty(BACKUP_CODES_CLAIM)).thenAnswer(arg -> {
            if (isInitialFedAttempt) {
                return HASHED_BACKUP_CODES;
            }
            return null;
        });
        when(mockUserStoreManager.getUserClaimValues(anyString(), anyObject(), anyString())).thenReturn(claims);
        doNothing().when(mockUserStoreManager).setUserClaimValues(any(), anyObject(), any());
        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        try {
            backupCodeAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mocHttpServletResponse,
                    mockAuthenticationContext);
            assertFalse(expectError);
        } catch (AuthenticationFailedException e) {
            assertTrue(expectError);
        }
    }

    @DataProvider(name = "processAuthenticationResponseData")
    public Object[][] dataForProcessAuthenticationResponse() {

        Map<String, String> claims = new HashMap<>();
        claims.put(BACKUP_CODES_CLAIM, HASHED_BACKUP_CODES);
        return new Object[][]{{VALID_TOKEN, FULL_QUALIFIED_USERNAME, true, false, false, claims, false},
                {INVALID_TOKEN, FULL_QUALIFIED_USERNAME, true, false, false, claims, true},
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, false, false, true, claims, false},
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, true, true, false, claims, true},
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, true, false, false, new HashMap<>(), true},
                {"", FULL_QUALIFIED_USERNAME, true, false, false, new HashMap<>(), true}};
    }

    @Test(dataProvider = "processData")
    public void testProcess(boolean isLogoutRequest, String backupCode, String authenticatorName, boolean isFedUser,
                            String username, boolean isProvisioningEnabled, Map<String, String> claims,
                            boolean authenticatedUserInContext, boolean isRetrying, Object expectedFlowStatus,
                            boolean expectError) throws BackupCodeException, UserStoreException {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(BackupCodeAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE, "false");
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig(
                "backup-code-authenticator", true, parameterMap);
        try {
            mockStatic(BackupCodeUtil.class);
            mockStatic(FederatedAuthenticatorUtil.class);
            mockStatic(BackupCodeDataHolder.class);
            mockStatic(IdentityCoreServiceComponent.class);
            mockStatic(CarbonUtils.class);
            mockStatic(FileBasedConfigurationBuilder.class);
            when(mockAuthenticationContext.isLogoutRequest()).thenReturn(isLogoutRequest);
            when(mockAuthenticationContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
            when(mockAuthenticationContext.getProperty(AUTHENTICATION)).thenReturn(authenticatorName);
            when(mockAuthenticationContext.isRetrying()).thenReturn(isRetrying);
            when(mockHttpServletRequest.getParameter(BACKUP_CODE)).thenReturn(backupCode);
            when(BackupCodeUtil.getAuthenticatedUser(any())).thenAnswer(arg -> {
                if (authenticatedUserInContext) {
                    return mockAuthenticatedUser;
                }
                return null;
            });
            when(BackupCodeUtil.getUserStoreManagerOfUser(anyString())).thenReturn(mockUserStoreManager);
            when(BackupCodeUtil.getBackupCodeLoginPage(anyObject())).thenReturn(
                    "https://localhost:9443/authenticationendpoint/backup_code.do");
            when(BackupCodeUtil.getBackupCodeErrorPage(anyObject())).thenReturn(
                    "https://localhost:9443/authenticationendpoint/backup_code_error.do");
            when(mockUserStoreManager.getUserClaimValues(anyString(), anyObject(), anyString())).thenReturn(claims);
            when(mockAuthenticatedUser.isFederatedUser()).thenReturn(isFedUser);
            when(mockAuthenticatedUser.getUserName()).thenReturn(username);
            when(mockAuthenticatedUser.getFederatedIdPName()).thenReturn("LOCAL");
            when(BackupCodeDataHolder.getIdpManager()).thenReturn(mockIdpManager);
            when(mockIdpManager.getIdPByName(anyString(), anyString())).thenReturn(mockIdentityProvider);
            when(mockIdentityProvider.getJustInTimeProvisioningConfig()).thenReturn(mockJustInTimeProvisioningConfig);
            when(mockJustInTimeProvisioningConfig.isProvisioningEnabled()).thenReturn(isProvisioningEnabled);
            when(FederatedAuthenticatorUtil.getLoggedInFederatedUser(any())).thenReturn(username);
            when(IdentityCoreServiceComponent.getConfigurationContextService()).thenReturn(
                    mockConfigurationContextService);
            when(mockConfigurationContextService.getServerConfigContext()).thenReturn(mockConfigurationContext);
            when(mockConfigurationContext.getAxisConfiguration()).thenReturn(mockAxisConfiguration);
            when(CarbonUtils.getTransportProxyPort((AxisConfiguration) anyObject(), anyString())).thenReturn(9443);
            when(FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(anyString(), any())).thenReturn(
                    username);
            when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
            when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);

            AuthenticatorFlowStatus flowStatus =
                    backupCodeAuthenticator.process(mockHttpServletRequest, mocHttpServletResponse,
                            mockAuthenticationContext);

            assertEquals(expectedFlowStatus, flowStatus);
            assertFalse(expectError);
        } catch (AuthenticationFailedException | LogoutFailedException e) {
            assertTrue(expectError);
        } catch (IdentityProviderManagementException e) {
            throw new RuntimeException(e);
        }
    }

    @DataProvider(name = "processData")
    public Object[][] dataForProcess() {

        Map<String, String> claims = new HashMap<>();
        claims.put(BACKUP_CODES_CLAIM, HASHED_BACKUP_CODES);
        return new Object[][]{
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.INCOMPLETE, false},
                {true, VALID_TOKEN, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED, false},
                {true, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED, false},
                {false, null, "totp", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED, false},
                {false, null, "backup-code-authenticator", true, "test@gmail.com", true, claims, true, false,
                        AuthenticatorFlowStatus.INCOMPLETE, false},
                {false, null, "backup-code-authenticator", true, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.FAIL_COMPLETED, true},
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, false, false,
                        AuthenticatorFlowStatus.FAIL_COMPLETED, true},
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, true,
                        AuthenticatorFlowStatus.INCOMPLETE, false},
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, new HashMap<>(), true, true,
                        AuthenticatorFlowStatus.INCOMPLETE, false}
        };
    }

    @Test(dataProvider = "initiateAuthenticationRequestWithErrorContextData")
    public void testInitiateAuthenticationRequestWithErrorContext(String showError, Boolean errorContextPresent,
                                                                  int failedAttempts, int maxAttempts,
                                                                  String lockedReason,
                                                                  Boolean hasErrorCode, String errorCodeParam,
                                                                  Boolean hasLockedReason, String lockedReasonParam)
            throws AuthenticationFailedException, BackupCodeException, UserStoreException, IOException {

        String username = "TEST-DOMAIN/test@gmail.com";
        Map<String, String> claims = new HashMap<>();
        claims.put(BACKUP_CODES_CLAIM, HASHED_BACKUP_CODES);

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(BackupCodeAuthenticatorConstants.CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE, showError);
        AuthenticatorConfig authenticatorConfig1 = new AuthenticatorConfig(
                "backup-code-authenticator", true, parameterMap);
        IdentityErrorMsgContext customErrorMessageContext = null;
        if (errorContextPresent) {
            customErrorMessageContext = new IdentityErrorMsgContext(
                    UserCoreConstants.ErrorCode.USER_IS_LOCKED + ":" + lockedReason,
                    failedAttempts, maxAttempts);
        }

        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(BackupCodeUtil.class);
        mockStatic(FederatedAuthenticatorUtil.class);
        mockStatic(IdentityUtil.class);
        when(BackupCodeUtil.getUserStoreManagerOfUser(anyString())).thenReturn(mockUserStoreManager);
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig1);
        when(mockAuthenticationContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
        when(BackupCodeUtil.getAuthenticatedUser(any())).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticatedUser.getUserName()).thenReturn(username);
        when(mockUserStoreManager.getUserClaimValues(anyString(), anyObject(), anyString())).thenReturn(claims);
        when(IdentityUtil.getIdentityErrorMsg()).thenReturn(customErrorMessageContext);
        when(mockAuthenticatedUser.isFederatedUser()).thenReturn(false);
        when(BackupCodeUtil.getBackupCodeLoginPage(anyObject())).thenReturn(
                "https://localhost:9443/authenticationendpoint/backup_code.do");
        when(BackupCodeUtil.getBackupCodeErrorPage(anyObject())).thenReturn(
                "https://localhost:9443/authenticationendpoint/backup_code_error.do");
        doAnswer((Answer<Object>) invocation -> {

            redirect = (String) invocation.getArguments()[0];
            return null;
        }).when(mocHttpServletResponse).sendRedirect(anyString());

        backupCodeAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mocHttpServletResponse,
                mockAuthenticationContext);

        assertFalse(hasErrorCode ^ redirect.contains(errorCodeParam));
        assertFalse(hasLockedReason ^ redirect.contains(lockedReasonParam));
    }

    @DataProvider(name="initiateAuthenticationRequestWithErrorContextData")
    public Object[][] DataForInitiateAuthenticationRequestWithErrorContext() {

        String maxAttemptsExceeded = BackupCodeAuthenticatorConstants.MAX_ATTEMPTS_EXCEEDED;
        String adminLocked = BackupCodeAuthenticatorConstants.ADMIN_INITIATED;
        String lockedErrorCode = UserCoreConstants.ErrorCode.USER_IS_LOCKED;

        return new Object[][]{
                {"true", true, 3, 3, "", true, "&errorCode=" + lockedErrorCode, true,
                        "&lockedReason=" + maxAttemptsExceeded},
                {"true", true, 0, 0, maxAttemptsExceeded, true, "&errorCode=" + lockedErrorCode, true,
                        "&lockedReason=" + maxAttemptsExceeded},
                {"true", true, 0, 0, adminLocked, true, "&errorCode=" + lockedErrorCode, true,
                        "&lockedReason=" + adminLocked},
                {"true", true, 0, 0, "", true, "&errorCode=" + lockedErrorCode, false, "lockedReason"},
                {"false", true, 3, 3, "", false, "errorCode", false, "lockedReason"},
                {"true", false, 3, 3, "", false, "errorCode", false, "lockedReason"}
        };
    }
}
