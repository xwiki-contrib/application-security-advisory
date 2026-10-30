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
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceSerializer;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;

/**
 * Reads and writes the users of the external systems advisories are imported from, and their mapping to XWiki users.
 * Each external user is stored in its own hidden page of the {@link #SPACE_NAMES} space, so that administrators can
 * filter, paginate and edit them with a live data. Since the mapping decides who is in charge of embargoed advisories,
 * the space is restricted to administrators (see {@link ExternalUsersRightsInitializer}), and a mapping is only taken
 * into account if the last author of its page is an administrator.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component(roles = ExternalUserMappingStore.class)
@Singleton
public class ExternalUserMappingStore
{
    /**
     * The space holding one page per external user.
     */
    public static final List<String> SPACE_NAMES =
        List.of(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CODE_SPACE_LIST.get(0), "ExternalUsers");

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private UserPropertyConverter userPropertyConverter;

    @Inject
    private AuthorizationManager authorizationManager;

    @Inject
    @Named("document")
    private UserReferenceSerializer<DocumentReference> userReferenceSerializer;

    /**
     * @param externalUser an external user
     * @return the reference of the page holding the external user and its mapping
     */
    public DocumentReference getReference(ExternalUser externalUser)
    {
        return new DocumentReference(String.format("%s-%s", externalUser.hint(), externalUser.id()),
            new SpaceReference(this.contextProvider.get().getWikiId(), SPACE_NAMES));
    }

    private XWikiDocument getDocument(ExternalUser externalUser) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        DocumentReference reference = getReference(externalUser);
        try {
            return context.getWiki().getDocument(reference, context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format("Cannot access the external user page [%s]", reference), e);
        }
    }

    private Optional<BaseObject> getObject(XWikiDocument document)
    {
        return Optional.ofNullable(
            document.getXObject(ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE));
    }

    private boolean isAuthoredByAdministrator(XWikiDocument document)
    {
        DocumentReference author =
            this.userReferenceSerializer.serialize(document.getAuthors().getEffectiveMetadataAuthor());
        return this.authorizationManager.hasAccess(Right.ADMIN, author,
            document.getDocumentReference().getWikiReference());
    }

    /**
     * @param externalUser a user of an external system, identified by the hint of the system and their identifier in
     *     it (their login is ignored since it can change)
     * @return the XWiki user mapped to the external user, or {@link Optional#empty()} if there's no mapping, or if the
     *     mapping was not saved by an administrator
     * @throws SecurityAdvisoryException in case of problem to read the external user page
     */
    public Optional<UserReference> getMappedUser(ExternalUser externalUser) throws SecurityAdvisoryException
    {
        XWikiDocument document = getDocument(externalUser);
        Optional<UserReference> result = getObject(document).flatMap(mappingObject -> this.userPropertyConverter
            .resolve(mappingObject.getLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER),
                document.getDocumentReference()));
        if (result.isPresent() && !isAuthoredByAdministrator(document)) {
            result = Optional.empty();
        }
        return result;
    }

    /**
     * @param externalUser a user of an external system
     * @return {@code true} if the external user has been archived, i.e. it's known that it cannot be mapped
     * @throws SecurityAdvisoryException in case of problem to read the external user page
     */
    public boolean isArchived(ExternalUser externalUser) throws SecurityAdvisoryException
    {
        return getObject(getDocument(externalUser))
            .map(mappingObject -> mappingObject.getIntValue(
                ExternalUserMappingClassMandatoryDocumentInitializer.ARCHIVED) == 1)
            .orElse(false);
    }

    /**
     * @param externalUsers the external users involved in an advisory, by order of priority
     * @return the XWiki user mapped to the first external user having a mapping, or {@link Optional#empty()} if none
     *     of them has a mapping
     * @throws SecurityAdvisoryException in case of problem to read the external user pages
     */
    public Optional<UserReference> resolveAssignee(List<ExternalUser> externalUsers) throws SecurityAdvisoryException
    {
        for (ExternalUser externalUser : externalUsers) {
            Optional<UserReference> mappedUser = getMappedUser(externalUser);
            if (mappedUser.isPresent()) {
                return mappedUser;
            }
        }
        return Optional.empty();
    }

    /**
     * Make sure a page exists for the given external user, so that administrators can find it and map it. The login
     * of an external user who is not mapped yet is updated if it changed; the page of a mapped user is left untouched,
     * so that the mapping stays authored by the administrator who saved it.
     *
     * @param externalUser the external user to register
     * @throws SecurityAdvisoryException in case of problem to save the external user page
     */
    public void register(ExternalUser externalUser) throws SecurityAdvisoryException
    {
        XWikiDocument document = getDocument(externalUser);
        Optional<BaseObject> mappingObject = getObject(document);
        boolean isMapped = mappingObject.map(object -> StringUtils.isNotBlank(
            object.getLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER))).orElse(false);
        boolean loginChanged = mappingObject.map(object -> !Objects.equals(externalUser.login(),
            object.getStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.LOGIN))).orElse(true);
        if (!isMapped && loginChanged) {
            save(externalUser, document, object -> { }, "Register external user");
        }
    }

    /**
     * Map the given external user to the given XWiki user, replacing the existing mapping of the external user if
     * any, and unarchive it.
     *
     * @param externalUser the external user to map
     * @param userReference the XWiki user to map the external user to
     * @throws SecurityAdvisoryException in case of problem to save the external user page
     */
    public void setMapping(ExternalUser externalUser, UserReference userReference) throws SecurityAdvisoryException
    {
        XWikiDocument document = getDocument(externalUser);
        String user = this.userPropertyConverter.serialize(userReference, document.getDocumentReference());
        save(externalUser, document, object -> {
            object.setLargeStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.USER, user);
            object.setIntValue(ExternalUserMappingClassMandatoryDocumentInitializer.ARCHIVED, 0);
        }, String.format("Map external user [%s]", externalUser.login()));
    }

    /**
     * @param externalUser the external user to archive or unarchive
     * @param archived {@code true} to archive the external user, i.e. to mark it as a user that cannot be mapped
     * @throws SecurityAdvisoryException in case of problem to save the external user page
     */
    public void setArchived(ExternalUser externalUser, boolean archived) throws SecurityAdvisoryException
    {
        save(externalUser, getDocument(externalUser),
            object -> object.setIntValue(ExternalUserMappingClassMandatoryDocumentInitializer.ARCHIVED,
                archived ? 1 : 0),
            String.format("%s external user [%s]", archived ? "Archive" : "Unarchive", externalUser.login()));
    }

    private void save(ExternalUser externalUser, XWikiDocument document, Consumer<BaseObject> update,
        String comment) throws SecurityAdvisoryException
    {
        XWikiContext context = this.contextProvider.get();
        XWikiDocument clonedDocument = document.clone();
        try {
            BaseObject mappingObject = clonedDocument.getXObject(
                ExternalUserMappingClassMandatoryDocumentInitializer.CLASS_REFERENCE, true, context);
            mappingObject.setStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.HINT,
                externalUser.hint());
            mappingObject.setStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.EXTERNAL_ID,
                externalUser.id());
            mappingObject.setStringValue(ExternalUserMappingClassMandatoryDocumentInitializer.LOGIN,
                externalUser.login());
            update.accept(mappingObject);
            clonedDocument.setHidden(true);
            context.getWiki().saveDocument(clonedDocument, comment, true, context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format("Cannot save the external user page [%s]", clonedDocument.getDocumentReference()), e);
        }
    }
}
