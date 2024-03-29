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
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATION;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.DISPLAY_BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT;

@PrepareForTest({BackupCodeAuthenticator.class, BackupCodeUtil.class, BackupCodeDataHolder.class,
        FileBasedConfigurationBuilder.class, IdentityUtil.class,
        FederatedAuthenticatorUtil.class, IdentityCoreServiceComponent.class, CarbonUtils.class, LoggerUtils.class})
public class BackupCodeAuthenticatorTest extends PowerMockTestCase {

    private static final String BACKUP_CODE_PARAM = "backup.code.param";
    @Mock
    HttpServletRequest mockHttpServletRequest;

    @Mock
   ExternalIdPConfig externalIdPConfig;
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
    BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();

    private static final String VALID_TOKEN = "234561";
    private static final String INVALID_TOKEN = "123456";
    private static final String FULL_QUALIFIED_USERNAME = "TEST-DOMAIN/test@gmail.com@carbon.super";
    private static final String USERNAME = "test@gmail.com";
    private static final String USER_ID = UUID.randomUUID().toString();
    private static final String HASHED_BACKUP_CODES =
            "2d578fa2a67a4e24933164a78752f9ea60cdbcbcb683637b582595e49d19a305,2dc0269fa54d269a87536810ec453cb095b4b92f45e63826a21dff1c2e76f169";
    private static final String TENANT_DOMAIN = "carbon.super";
    private static final String QUERY_PARAMS = "client_id=MY_ACCOUNT&commonAuthCallerPath=%2Foauth2%2Fauthorize&forceAuth=false&passiveAuth=false&redirect_uri=https%3A%2F%2Flocalhost%2Fapp&t=testDomain&sp=application";
    private static final String QUERY_PARAMS_WITHOUT_SP_T = "client_id=MY_ACCOUNT&commonAuthCallerPath=%2Foauth2%2Fauthorize&forceAuth=false&passiveAuth=false&redirect_uri=https%3A%2F%2Flocalhost%2Fapp";
    private String redirect;

    @BeforeMethod
    public void setUp() {

        mockStatic(LoggerUtils.class);
    }

    @Test(dataProvider = "canHandleData")
    public void testCanHandleWithDiagnosticLog(String backupCode, boolean expectedValue) {

        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        testCanHandle(backupCode, expectedValue);
    }

    @Test(dataProvider = "canHandleData")
    public void testCanHandleWithoutDiagnosticLog(String backupCode, boolean expectedValue) {

        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(false);
        testCanHandle(backupCode, expectedValue);
    }

    private void testCanHandle(String backupCode, boolean expectedValue) {

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
    public void testProcessAuthResponseWithDiagnosticLog(String token, String fullyQualifiedUserName,
                                                         String username, String userId, boolean isLocalUser,
                                                         boolean isAccountLock, boolean isInitialFedAttempt,
                                                         Map<String, String> claims, boolean expectError,
                                                         String queryParams)
            throws IdentityEventException, UserStoreException, UserIdNotFoundException {

        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        testProcessAuthenticationResponse(token, fullyQualifiedUserName, username, userId, isLocalUser, isAccountLock,
                isInitialFedAttempt, claims, expectError, queryParams);
    }

    @Test(dataProvider = "processAuthenticationResponseData")
    public void testProcessAuthResponseWithoutDiagnosticLog(String token, String fullyQualifiedUserName,
                                                            String username, String userId, boolean isLocalUser,
                                                            boolean isAccountLock, boolean isInitialFedAttempt,
                                                            Map<String, String> claims, boolean expectError,
                                                            String queryParams)
            throws IdentityEventException, UserStoreException, UserIdNotFoundException {

        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(false);
        testProcessAuthenticationResponse(token, fullyQualifiedUserName, username, userId, isLocalUser, isAccountLock,
                isInitialFedAttempt, claims, expectError, queryParams);
    }

    private void testProcessAuthenticationResponse(String token, String fullyQualifiedUserName, String username,
                                                  String userId, boolean isLocalUser, boolean isAccountLock,
                                                  boolean isInitialFedAttempt, Map<String, String> claims,
                                                  boolean expectError, String queryParams)
            throws IdentityEventException, UserStoreException, UserIdNotFoundException {

        mockStatic(BackupCodeUtil.class, CALLS_REAL_METHODS);
        mockStatic(BackupCodeDataHolder.class);
        when(mockHttpServletRequest.getParameter(BACKUP_CODE)).thenReturn(token);
        when(mockAuthenticationContext.getProperty(AUTHENTICATED_USER)).thenReturn(mockAuthenticatedUser);
        when(mockAuthenticationContext.getQueryParams()).thenReturn(queryParams);
        when(mockAuthenticatedUser.toFullQualifiedUsername()).thenReturn(fullyQualifiedUserName);
        when(mockAuthenticatedUser.getUserName()).thenReturn(username);
        when(mockAuthenticatedUser.getUserId()).thenReturn(userId);
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
        return new Object[][]{
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, USERNAME, null, true, false, false, claims, false, QUERY_PARAMS},
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, USERNAME, null, true, false, false, claims, false, QUERY_PARAMS_WITHOUT_SP_T},
                {INVALID_TOKEN, FULL_QUALIFIED_USERNAME, USERNAME, USER_ID, true, false, false, claims, true, QUERY_PARAMS},
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, USERNAME, USER_ID, false, false, true, claims, false, QUERY_PARAMS},
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, USERNAME, USER_ID, true, true, false, claims, true, QUERY_PARAMS},
                {VALID_TOKEN, FULL_QUALIFIED_USERNAME, USERNAME, USER_ID, true, false, false, new HashMap<>(), true, QUERY_PARAMS},
                {"", FULL_QUALIFIED_USERNAME, USERNAME, null, true, false, false, new HashMap<>(), true, QUERY_PARAMS}};
    }

    @Test(dataProvider = "processData")
    public void testProcessWithDiagnosticLog(boolean isLogoutRequest, String backupCode, String authenticatorName,
                                             boolean isFedUser, String username, boolean isProvisioningEnabled,
                                             Map<String, String> claims, boolean authenticatedUserInContext,
                                             boolean isRetrying, Object expectedFlowStatus, boolean expectError,
                                             String queryParams)
            throws BackupCodeException, UserStoreException {
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        testProcess(isLogoutRequest, backupCode, authenticatorName, isFedUser, username, isProvisioningEnabled, claims,
                authenticatedUserInContext, isRetrying, expectedFlowStatus, expectError, queryParams);
    }

    @Test(dataProvider = "processData")
    public void testProcessWithOutDiagnosticLog(boolean isLogoutRequest, String backupCode, String authenticatorName,
                                                boolean isFedUser, String username, boolean isProvisioningEnabled,
                                                Map<String, String> claims, boolean authenticatedUserInContext,
                                                boolean isRetrying, Object expectedFlowStatus, boolean expectError,
                                                String queryParams)
            throws BackupCodeException, UserStoreException {
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(false);
        testProcess(isLogoutRequest, backupCode, authenticatorName, isFedUser, username, isProvisioningEnabled, claims,
                authenticatedUserInContext, isRetrying, expectedFlowStatus, expectError, queryParams);
    }

    private void testProcess(boolean isLogoutRequest, String backupCode, String authenticatorName, boolean isFedUser,
                            String username, boolean isProvisioningEnabled, Map<String, String> claims,
                            boolean authenticatedUserInContext, boolean isRetrying, Object expectedFlowStatus,
                            boolean expectError, String queryParams) throws BackupCodeException, UserStoreException {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FrameworkConstants.SHOW_AUTHFAILURE_RESON_CONFIG, String.valueOf(false));
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig(
                BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_NAME, true, parameterMap);
        try {
            mockStatic(BackupCodeUtil.class);
            mockStatic(FederatedAuthenticatorUtil.class);
            mockStatic(BackupCodeDataHolder.class);
            mockStatic(IdentityCoreServiceComponent.class);
            mockStatic(CarbonUtils.class);
            mockStatic(FileBasedConfigurationBuilder.class);
            when(mockAuthenticationContext.isLogoutRequest()).thenReturn(isLogoutRequest);
            when(mockAuthenticationContext.getLoginTenantDomain()).thenReturn(TENANT_DOMAIN);
            when(mockAuthenticationContext.getProperty(AUTHENTICATION)).thenReturn(authenticatorName);
            when(mockAuthenticationContext.isRetrying()).thenReturn(isRetrying);
            when(mockAuthenticationContext.getQueryParams()).thenReturn(queryParams);
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
                        AuthenticatorFlowStatus.INCOMPLETE, false, QUERY_PARAMS},
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.INCOMPLETE, false, QUERY_PARAMS_WITHOUT_SP_T},
                {true, VALID_TOKEN, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED, false, QUERY_PARAMS},
                {true, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED, false, QUERY_PARAMS},
                {false, null, "totp", false, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.SUCCESS_COMPLETED, false, QUERY_PARAMS},
                {false, null, "backup-code-authenticator", true, "test@gmail.com", true, claims, true, false,
                        AuthenticatorFlowStatus.INCOMPLETE, false, QUERY_PARAMS},
                {false, null, "backup-code-authenticator", true, "test@gmail.com", false, claims, true, false,
                        AuthenticatorFlowStatus.FAIL_COMPLETED, true, QUERY_PARAMS},
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, false, false,
                        AuthenticatorFlowStatus.FAIL_COMPLETED, true, QUERY_PARAMS},
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, claims, true, true,
                        AuthenticatorFlowStatus.INCOMPLETE, false, QUERY_PARAMS},
                {false, null, "backup-code-authenticator", false, "test@gmail.com", false, new HashMap<>(), true, true,
                        AuthenticatorFlowStatus.INCOMPLETE, false, QUERY_PARAMS}
        };
    }

    @Test(dataProvider = "initiateAuthenticationRequestWithErrorContextData")
    public void testInitAuthRequestErrorHandlingWithDiagnosticLog(boolean showError, boolean showErrorOnLoginPage,
                                                                   boolean errorContextPresent, int failedAttempts,
                                                                   int maxAttempts, String lockedReason,
                                                                   boolean hasErrorCode, String errorCodeParam,
                                                                   boolean hasLockedReason, String lockedReasonParam)
            throws AuthenticationFailedException, BackupCodeException, UserStoreException, IOException {

        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
        testInitiateAuthenticationRequestWithErrorContext(showError, showErrorOnLoginPage, errorContextPresent,
                failedAttempts, maxAttempts, lockedReason, hasErrorCode, errorCodeParam, hasLockedReason,
                lockedReasonParam);
    }

    @Test(dataProvider = "initiateAuthenticationRequestWithErrorContextData")
    public void testInitAuthRequestErrorHandlingWithOutDiagnosticLog(boolean showError, boolean showErrorOnLoginPage,
                                                                     boolean errorContextPresent, int failedAttempts,
                                                                     int maxAttempts, String lockedReason,
                                                                     boolean hasErrorCode, String errorCodeParam,
                                                                     boolean hasLockedReason, String lockedReasonParam)
            throws AuthenticationFailedException, BackupCodeException, UserStoreException, IOException {

        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(false);
        testInitiateAuthenticationRequestWithErrorContext(showError, showErrorOnLoginPage, errorContextPresent,
                failedAttempts, maxAttempts, lockedReason, hasErrorCode, errorCodeParam, hasLockedReason,
                lockedReasonParam);
    }

    private void testInitiateAuthenticationRequestWithErrorContext(boolean showError, boolean showErrorOnLoginPage,
                                                                   boolean errorContextPresent, int failedAttempts,
                                                                   int maxAttempts, String lockedReason,
                                                                   boolean hasErrorCode, String errorCodeParam,
                                                                   boolean hasLockedReason, String lockedReasonParam)
            throws AuthenticationFailedException, BackupCodeException, UserStoreException, IOException {

        String username = "TEST-DOMAIN/test@gmail.com";
        Map<String, String> claims = new HashMap<>();
        claims.put(BACKUP_CODES_CLAIM, HASHED_BACKUP_CODES);

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        Map<String, String> parameterMap = new HashMap<>();
        parameterMap.put(FrameworkConstants.SHOW_AUTHFAILURE_RESON_CONFIG, String.valueOf(showError));
        parameterMap.put(FrameworkConstants.SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE_CONF,
                String.valueOf(showErrorOnLoginPage));
        AuthenticatorConfig authenticatorConfig1 = new AuthenticatorConfig(
                BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_NAME, true, parameterMap);
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
        when(mockAuthenticationContext.getLoginTenantDomain()).thenReturn(TENANT_DOMAIN);
        when(mockAuthenticationContext.getQueryParams()).thenReturn(QUERY_PARAMS);
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
                {true, true, true, 3, 3, "", true, "&errorCode=" + lockedErrorCode, true,
                        "&lockedReason=" + maxAttemptsExceeded},
                {false, true, true, 3, 3, "", false, "errorCode", false, "lockedReason"},
                {true, true, true, 0, 0, maxAttemptsExceeded, true, "&errorCode=" + lockedErrorCode, true,
                        "&lockedReason=" + maxAttemptsExceeded},
                {true, true, true, 0, 0, adminLocked, true, "&errorCode=" + lockedErrorCode, true,
                        "&lockedReason=" + adminLocked},
                {true, true, true, 0, 0, "", true, "&errorCode=" + lockedErrorCode, true,
                        "&lockedReason=" + maxAttemptsExceeded},
                {true, false, true, 3, 3, "", false, "errorCode", false, "lockedReason"},
                {true, true, false, 3, 3, "", false, "errorCode", false, "lockedReason"}
        };
    }

    @Test
    public void testIsAPIBasedAuthenticationSupported() {

        boolean isAPIBasedAuthenticationSupported = backupCodeAuthenticator.isAPIBasedAuthenticationSupported();
        Assert.assertTrue(isAPIBasedAuthenticationSupported);
    }

    @Test
    public void testGetAuthInitiationData() {

        when(mockAuthenticationContext.getExternalIdP()).thenReturn(externalIdPConfig);
        when(externalIdPConfig.getIdPName()).thenReturn("LOCAL");
        Optional<AuthenticatorData> authenticatorData = backupCodeAuthenticator.
                getAuthInitiationData(mockAuthenticationContext);

        Assert.assertTrue(authenticatorData.isPresent());
        AuthenticatorData authenticatorDataObj = authenticatorData.get();

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata codeMetadata = new AuthenticatorParamMetadata(
                BACKUP_CODE, DISPLAY_BACKUP_CODE, FrameworkConstants.AuthenticatorParamType.STRING,
                1, Boolean.TRUE, BACKUP_CODE_PARAM);
        authenticatorParamMetadataList.add(codeMetadata);
        Assert.assertEquals(authenticatorDataObj.getRequiredParams().size(), 1);
        Assert.assertEquals(authenticatorDataObj.getAuthParams().size(), authenticatorParamMetadataList.size(),
                "Size of lists should be equal.");
        for (int i = 0; i < authenticatorParamMetadataList.size(); i++) {
            AuthenticatorParamMetadata expectedParam = authenticatorParamMetadataList.get(i);
            AuthenticatorParamMetadata actualParam = authenticatorDataObj.getAuthParams().get(i);
            Assert.assertEquals(actualParam.getName(), expectedParam.getName(), "Parameter name should match.");
            Assert.assertEquals(actualParam.getType(), expectedParam.getType(), "Parameter type should match.");
            Assert.assertEquals(actualParam.getParamOrder(), expectedParam.getParamOrder(),
                    "Parameter order should match.");
            Assert.assertEquals(actualParam.isConfidential(), expectedParam.isConfidential(),
                    "Parameter mandatory status should match.");
        }
    }
}
