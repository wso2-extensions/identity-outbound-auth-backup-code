/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeClientException;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserStoreClientException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.AuditLog;
import org.wso2.carbon.utils.DiagnosticLog;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_ENABLED_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.ENABLED_AUTHENTICATORS_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_ACCESS_USER_REALM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_BACKUP_CODE_UPDATE_FAILURE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_NO_USER_ID;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_SETTING_USER_CLAIM_VALUES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_NO_USERNAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LogConstants.ActionIDs.DELETE_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LogConstants.ActionIDs.GENERATE_BACKUP_CODES;
import static org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils.triggerAuditLogEvent;

/**
 * Handle backup code API related functionalities.
 */
public class BackupCodeAPIHandler {

    private static final String BACKUP_CODE_SEPARATOR = ",";

    private static String getAuditInitiatorId() {

        String user = CarbonContext.getThreadLocalCarbonContext().getUsername();
        if (StringUtils.isNotBlank(user)) {
            user = UserCoreUtil.addTenantDomainToEntry(user,
                    CarbonContext.getThreadLocalCarbonContext().getTenantDomain());
        } else {
            user = CarbonConstants.REGISTRY_SYSTEM_USERNAME;
        }
        String initiator = null;
        String username = MultitenantUtils.getTenantAwareUsername(user);
        String tenantDomain = MultitenantUtils.getTenantDomain(user);
        if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(tenantDomain)) {
            initiator = IdentityUtil.getInitiatorId(username, tenantDomain);
        }
        if (StringUtils.isBlank(initiator)) {
            if (username.equals(CarbonConstants.REGISTRY_SYSTEM_USERNAME)) {
                // If the initiator is wso2.system, we need not mask the username.
                return LoggerUtils.Initiator.System.name();
            }
            initiator = LoggerUtils.getMaskedContent(user);
        }
        return initiator;
    }

    private static AuditLog.AuditLogBuilder buildAuditLogBuilder(String resourceId, String actionId) {

        String initiatorId = getAuditInitiatorId();
        return new AuditLog.AuditLogBuilder(
                initiatorId,
                LoggerUtils.getInitiatorType(initiatorId),
                resourceId,
                LoggerUtils.Target.User.name(),
                actionId);
    }

    /**
     * Returns the number of backup codes remaining for the given user.
     *
     * @param username Username of the user.
     * @return the number of backup codes remaining for the given user.
     * @throws BackupCodeException If an error occurred while getting backup codes.
     */
    public static int getRemainingBackupCodesCount(String username) throws BackupCodeException {

        try {
            if (StringUtils.isBlank(username)) {
                throw new BackupCodeClientException(ERROR_NO_USERNAME.getCode(),
                        String.format(ERROR_NO_USERNAME.getMessage()));
            }
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            Map<String, String> userClaimValues = BackupCodeUtil.getUserStoreManagerOfUser(username)
                    .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
            String backupCodes = userClaimValues.get(BACKUP_CODES_CLAIM);
            List<String> remainingBackupCodesList = new ArrayList<>();
            if (StringUtils.isNotBlank(backupCodes)) {
                remainingBackupCodesList.addAll(Arrays.asList(backupCodes.split(BACKUP_CODE_SEPARATOR)));
            }
            return remainingBackupCodesList.size();
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
    }

    /**
     * Generate backup codes for the user.
     *
     * @param username Username of the user.
     * @return list of generated backup codes for the user.
     * @throws BackupCodeException If an error occurred while generating the backup codes.
     */
    public static List<String> generateBackupCodes(String username) throws BackupCodeException {

        List<String> generatedBackupCodes;
        if (StringUtils.isBlank(username)) {
            throw new BackupCodeClientException(ERROR_NO_USERNAME.getCode(),
                    String.format(ERROR_NO_USERNAME.getMessage()));
        }
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        generatedBackupCodes = BackupCodeUtil.generateBackupCodes(tenantDomain);
        ArrayList<String> hashedBackupCodesList = new ArrayList<>();
        for (String backupCode : generatedBackupCodes) {
            hashedBackupCodesList.add(BackupCodeUtil.generateHashBackupCode(backupCode));
        }
        updateUserBackupCodes(username, String.join(BACKUP_CODE_SEPARATOR, hashedBackupCodesList),
                "true");
        return generatedBackupCodes;
    }

    /**
     * Remove the stored remaining backup codes for the user.
     *
     * @param username username of the user.
     * @return true if successfully resetting the claims, false otherwise.
     * @throws BackupCodeException when user realm is null for given tenant domain.
     */
    public static boolean deleteBackupCodes(String username) throws BackupCodeException {

        if (StringUtils.isBlank(username)) {
            throw new BackupCodeClientException(ERROR_NO_USERNAME.getCode(),
                    String.format(ERROR_NO_USERNAME.getMessage()));
        }
        updateUserBackupCodes(username, StringUtils.EMPTY, "false");
        return true;
    }

    /**
     * Update user claims for the user.
     *
     * @param username username of the user.
     * @throws BackupCodeException when user realm is null for given tenant domain or when an error occurred while
     * updating user claims.
     */
    private static void updateUserBackupCodes(String username, String backupCodes, String isBackupCodesEnabled)
            throws BackupCodeException {

            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            Map<String, String> claims = new HashMap<>();
                claims.put(BACKUP_CODES_CLAIM, backupCodes);
                claims.put(BACKUP_CODES_ENABLED_CLAIM, isBackupCodesEnabled);
        try {
            BackupCodeUtil.getUserStoreManagerOfUser(username).setUserClaimValues(tenantAwareUsername,
                    claims, null);
        } catch (UserStoreException e) {
            throw new BackupCodeClientException(ERROR_SETTING_USER_CLAIM_VALUES.getCode(),
                    String.format(ERROR_SETTING_USER_CLAIM_VALUES.getMessage()));
        }
    }

    /**
     * Returns the number of backup codes remaining for the user identified by the given userID.
     *
     * @param userId       Unique ID of the user.
     * @return The number of backup codes remaining for the user.
     * @throws BackupCodeException If an error occurred while reading the backup codes claim.
     */
    public static int getRemainingBackupCodesCountByUserId(String userId) throws BackupCodeException {

        if (StringUtils.isBlank(userId)) {
            throw new BackupCodeClientException(ERROR_NO_USER_ID.getCode(),
                    String.format(ERROR_NO_USER_ID.getMessage()));
        }
        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        try {
            UniqueIDUserStoreManager userStoreManager = BackupCodeUtil.getUserStoreManagerOfTenant(tenantDomain);
            Map<String, String> userClaimValues = userStoreManager
                    .getUserClaimValuesWithID(userId, new String[]{BACKUP_CODES_CLAIM}, null);
            String backupCodes = userClaimValues.get(BACKUP_CODES_CLAIM);
            return StringUtils.isBlank(backupCodes) ? 0 : backupCodes.split(BACKUP_CODE_SEPARATOR).length;
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), userId, e));
        }
    }

    /**
     * Generate backup codes for the user identified by the given userID.
     *
     * @param userId       Unique ID of the user.
     * @return List of generated plain-text backup codes (to be displayed once to the user).
     * @throws BackupCodeException If an error occurred while generating the backup codes.
     */
    public static List<String> generateBackupCodesByUserId(String userId)
            throws BackupCodeException {

        if (StringUtils.isBlank(userId)) {
            throw new BackupCodeClientException(ERROR_NO_USER_ID.getCode(),
                    String.format(ERROR_NO_USER_ID.getMessage()));
        }
        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        UniqueIDUserStoreManager userStoreManager = BackupCodeUtil.getUserStoreManagerOfTenant(tenantDomain);
        List<String> generatedBackupCodes = BackupCodeUtil.generateBackupCodes(tenantDomain);
        ArrayList<String> hashedBackupCodesList = new ArrayList<>();
        for (String backupCode : generatedBackupCodes) {
            hashedBackupCodesList.add(BackupCodeUtil.generateHashBackupCode(backupCode));
        }
        String enabledAuthenticators = appendAuthenticator(getCurrentEnabledAuthenticators(userId, userStoreManager));
        updateUserBackupCodesByUserId(userId, String.join(BACKUP_CODE_SEPARATOR, hashedBackupCodesList),
                "true", enabledAuthenticators, userStoreManager);
        triggerAuditLogEvent(buildAuditLogBuilder(userId, GENERATE_BACKUP_CODES));
        return generatedBackupCodes;
    }

    /**
     * Remove the stored remaining backup codes for the user identified by the given userID.
     *
     * @param userId       Unique ID of the user.
     * @return {@code true} once the claims are reset.
     * @throws BackupCodeException If an error occurred while clearing the backup codes claim.
     */
    public static boolean deleteBackupCodesByUserId(String userId) throws BackupCodeException {

        if (StringUtils.isBlank(userId)) {
            throw new BackupCodeClientException(ERROR_NO_USER_ID.getCode(),
                    String.format(ERROR_NO_USER_ID.getMessage()));
        }
        String tenantDomain = IdentityTenantUtil.resolveTenantDomain();
        UniqueIDUserStoreManager userStoreManager = BackupCodeUtil.getUserStoreManagerOfTenant(tenantDomain);
        String enabledAuthenticators = removeAuthenticator(getCurrentEnabledAuthenticators(userId, userStoreManager));
        updateUserBackupCodesByUserId(userId, StringUtils.EMPTY, "false", enabledAuthenticators,
                userStoreManager);
        triggerAuditLogEvent(buildAuditLogBuilder(userId, DELETE_BACKUP_CODES));
        return true;
    }

    /**
     * Write the backup-code claims for the user identified by the given userID.
     *
     * @param userId                Unique ID of the user.
     * @param backupCodes           Comma-separated hashed backup codes (empty string clears the claim).
     * @param isBackupCodesEnabled  "true" or "false".
     * @param enabledAuthenticators Updated value for the enabledAuthenticators claim.
     * @param userStoreManager      Resolved user store manager for the user's tenant.
     * @throws BackupCodeException If the claim write fails.
     */
    private static void updateUserBackupCodesByUserId(String userId, String backupCodes,
                                                      String isBackupCodesEnabled, String enabledAuthenticators,
                                                      UniqueIDUserStoreManager userStoreManager)
            throws BackupCodeException {

        Map<String, String> claims = new HashMap<>();
        claims.put(BACKUP_CODES_CLAIM, backupCodes);
        claims.put(BACKUP_CODES_ENABLED_CLAIM, isBackupCodesEnabled);
        claims.put(ENABLED_AUTHENTICATORS_CLAIM, enabledAuthenticators);
        try {
            userStoreManager.setUserClaimValuesWithID(userId, claims, null);
        } catch (UserStoreClientException e) {
            throw new BackupCodeClientException(ERROR_BACKUP_CODE_UPDATE_FAILURE.getCode(),
                    String.format(ERROR_BACKUP_CODE_UPDATE_FAILURE.getMessage(), userId));
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_SETTING_USER_CLAIM_VALUES.getCode(),
                    ERROR_SETTING_USER_CLAIM_VALUES.getMessage(), e);
        }
    }

    /**
     * Retrieve the current value of the enabledAuthenticators claim for the given user.
     *
     * @param userId           Unique ID of the user.
     * @param userStoreManager Resolved user store manager for the user's tenant.
     * @return Current claim value, or {@code null} if the claim is not set.
     * @throws BackupCodeException If the claim read fails.
     */
    private static String getCurrentEnabledAuthenticators(String userId, UniqueIDUserStoreManager userStoreManager)
            throws BackupCodeException {

        try {
            Map<String, String> claims = userStoreManager.getUserClaimValuesWithID(userId,
                    new String[]{ENABLED_AUTHENTICATORS_CLAIM}, null);
            return claims.get(ENABLED_AUTHENTICATORS_CLAIM);
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), userId, e));
        }
    }

    /**
     * Append backup-code-authenticator to a comma-separated list of enabled authenticators if not already present.
     *
     * @param enabledAuthenticators Current comma-separated authenticator list (may be null or blank).
     * @return Updated comma-separated authenticator list.
     */
    private static String appendAuthenticator(String enabledAuthenticators) {

        if (StringUtils.isBlank(enabledAuthenticators)) {
            return BACKUP_CODE_AUTHENTICATOR_NAME;
        }
        List<String> authenticators = new ArrayList<>(Arrays.asList(enabledAuthenticators.split(",")));
        if (!authenticators.contains(BACKUP_CODE_AUTHENTICATOR_NAME)) {
            authenticators.add(BACKUP_CODE_AUTHENTICATOR_NAME);
        }
        return String.join(",", authenticators);
    }

    /**
     * Remove backup-code-authenticator from a comma-separated list of enabled authenticators.
     *
     * @param enabledAuthenticators Current comma-separated authenticator list (may be null or blank).
     * @return Updated comma-separated authenticator list, or empty string if none remain.
     */
    private static String removeAuthenticator(String enabledAuthenticators) {

        if (StringUtils.isBlank(enabledAuthenticators)) {
            return StringUtils.EMPTY;
        }
        List<String> authenticators = new ArrayList<>(Arrays.asList(enabledAuthenticators.split(",")));
        authenticators.remove(BACKUP_CODE_AUTHENTICATOR_NAME);
        return String.join(",", authenticators);
    }
}
