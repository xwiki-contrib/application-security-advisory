/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.securityadvisory.internal.assignee;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.internal.configuration.SecurityAdvisoryConfigurationSource;
import org.xwiki.user.UserReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;

/**
 * Reads and writes the mapping between the users of the external system advisories are imported from and the XWiki
 * users. The mapping is stored in the configuration document of the application, which only administrators should be
 * able to edit: since it decides who is in charge of embargoed advisories, users must not be able to declare their
 * own mapping.
 *
 * @version $Id$
 * @since 2.2.2
 */
@Component(roles = ExternalUserMappingStore.class)
@Singleton
public class ExternalUserMappingStore
{
    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private UserPropertyConverter userPropertyConverter;

    private XWikiDocument getConfigurationDocument() throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        try {
            return context.getWiki().getDocument(SecurityAdvisoryConfigurationSource.DOC_REFERENCE, context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException("Cannot access configuration document", e);
        }
    }

    private Optional<BaseObject> findMappingObject(XWikiDocument configurationDocument, String externalId)
    {
        return configurationDocument.getXObjects(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE)
            .stream()
            .filter(Objects::nonNull)
            .filter(mappingObject -> Objects.equals(externalId,
                mappingObject.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.EXTERNAL_ID)))
            .findFirst();
    }

    /**
     * @param externalId the stable identifier of a user in the external system
     * @return the XWiki user mapped to the external user, or {@link Optional#empty()} if there's no mapping
     * @throws SecurityAdvisoryException in case of problem to read the configuration document
     */
    public Optional<UserReference> getMappedUser(String externalId) throws SecurityAdvisoryException
    {
        XWikiDocument configurationDocument = getConfigurationDocument();
        return findMappingObject(configurationDocument, externalId)
            .flatMap(mappingObject -> this.userPropertyConverter.resolve(
                mappingObject.getLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER),
                configurationDocument.getDocumentReference()));
    }

    /**
     * @param externalUsers the external users involved in an advisory, by order of priority
     * @return the XWiki user mapped to the first external user having a mapping, or {@link Optional#empty()} if none
     *     of them has a mapping
     * @throws SecurityAdvisoryException in case of problem to read the configuration document
     */
    public Optional<UserReference> resolveAssignee(List<ExternalUser> externalUsers) throws SecurityAdvisoryException
    {
        for (ExternalUser externalUser : externalUsers) {
            Optional<UserReference> mappedUser = getMappedUser(externalUser.id());
            if (mappedUser.isPresent()) {
                return mappedUser;
            }
        }
        return Optional.empty();
    }

    /**
     * Map the given external user to the given XWiki user, replacing the existing mapping of the external user if
     * any.
     *
     * @param externalUser the external user to map
     * @param userReference the XWiki user to map the external user to
     * @throws SecurityAdvisoryException in case of problem to save the configuration document
     */
    public void setMapping(ExternalUser externalUser, UserReference userReference) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        XWikiDocument configurationDocument = getConfigurationDocument().clone();
        try {
            BaseObject mappingObject = findMappingObject(configurationDocument, externalUser.id()).orElse(null);
            if (mappingObject == null) {
                mappingObject = configurationDocument.newXObject(
                    ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE, context);
                mappingObject.setStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.EXTERNAL_ID,
                    externalUser.id());
            }
            mappingObject.setStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.LOGIN,
                externalUser.login());
            mappingObject.setLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER,
                this.userPropertyConverter.serialize(userReference, configurationDocument.getDocumentReference()));
            context.getWiki().saveDocument(configurationDocument,
                String.format("Map external user [%s]", externalUser.login()), true, context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format("Cannot save the mapping of external user [%s]", externalUser.login()), e);
        }
    }
}
