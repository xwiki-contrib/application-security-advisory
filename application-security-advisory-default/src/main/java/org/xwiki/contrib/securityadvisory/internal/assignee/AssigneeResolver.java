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

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.ExternalUser;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoriesManager;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer;
import org.xwiki.model.document.DocumentAuthors;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.user.UserReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;

/**
 * Resolves the assignee of the advisories which don't have one, from the mapping of their external users, and lists
 * the external users preventing advisories from being assigned because they have no mapping.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component(roles = AssigneeResolver.class)
@Singleton
public class AssigneeResolver
{
    @Inject
    private SecurityAdvisoriesManager securityAdvisoriesManager;

    @Inject
    private ExternalUserMappingStore externalUserMappingStore;

    @Inject
    private UserPropertyConverter userPropertyConverter;

    @Inject
    private QueryManager queryManager;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    @Named("compactwiki")
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private Provider<XWikiContext> contextProvider;

    /**
     * @param advisory an advisory
     * @return the external users of the advisory without mapping and not archived, by order of priority, or an empty
     *     list if the advisory already has an assignee
     * @throws SecurityAdvisoryException in case of problem to read the mapping
     */
    public List<ExternalUser> getUnmappedExternalUsers(SecurityAdvisory advisory) throws SecurityAdvisoryException
    {
        List<ExternalUser> result = new ArrayList<>();
        if (advisory.getAssignee() == null) {
            for (ExternalUser externalUser : advisory.getExternalUsers()) {
                if (this.externalUserMappingStore.getMappedUser(externalUser).isEmpty()
                    && !this.externalUserMappingStore.isArchived(externalUser))
                {
                    result.add(externalUser);
                }
            }
        }
        return result;
    }

    /**
     * @param externalUser an external user
     * @return the number of advisories without assignee the external user is involved in
     * @throws SecurityAdvisoryException in case of problem to query or load the advisories
     */
    public int countUnassignedAdvisories(ExternalUser externalUser) throws SecurityAdvisoryException
    {
        String statement = String.format("from doc.object(%s) as externalUser where externalUser.%s = :hint and "
            + "externalUser.%s = :externalId",
            this.entityReferenceSerializer.serialize(ExternalUserClassMandatoryDocumentInitializer.CLASS_REFERENCE),
            ExternalUserClassMandatoryDocumentInitializer.HINT,
            ExternalUserClassMandatoryDocumentInitializer.EXTERNAL_ID);
        try {
            return getUnassignedAdvisories(this.queryManager.createQuery(statement, Query.XWQL)
                .bindValue("hint", externalUser.hint())
                .bindValue("externalId", externalUser.id())).size();
        } catch (QueryException e) {
            throw new SecurityAdvisoryException(
                String.format("Error when counting the advisories of external user [%s]", externalUser.login()), e);
        }
    }

    /**
     * @return the advisories which have external users but no assignee
     * @throws SecurityAdvisoryException in case of problem to query or load the advisories
     */
    public List<SecurityAdvisory> getUnassignedAdvisories() throws SecurityAdvisoryException
    {
        String statement = String.format("from doc.object(%s) as externalUser",
            this.entityReferenceSerializer.serialize(ExternalUserClassMandatoryDocumentInitializer.CLASS_REFERENCE));
        try {
            return getUnassignedAdvisories(this.queryManager.createQuery(statement, Query.XWQL));
        } catch (QueryException e) {
            throw new SecurityAdvisoryException("Error when retrieving the advisories with external users", e);
        }
    }

    private List<SecurityAdvisory> getUnassignedAdvisories(Query query)
        throws QueryException, SecurityAdvisoryException
    {
        List<SecurityAdvisory> result = new ArrayList<>();
        // The query returns a document once per external user object it holds.
        Set<String> documentNames = new LinkedHashSet<>(query.execute());
        for (String documentName : documentNames) {
            this.securityAdvisoriesManager.loadAdvisory(this.documentReferenceResolver.resolve(documentName))
                .filter(advisory -> advisory.getAssignee() == null)
                .ifPresent(result::add);
        }
        return result;
    }

    /**
     * Set the assignee of the given advisory from the mapping of its external users, if it doesn't have an assignee
     * yet and one of its external users has a mapping.
     *
     * @param advisoryReference the reference of the document holding the advisory
     * @param author the user to record as author of the change
     * @return {@code true} if the assignee has been set, {@code false} otherwise
     * @throws SecurityAdvisoryException in case of problem to load or save the advisory
     */
    public boolean resolveAssignee(DocumentReference advisoryReference, UserReference author)
        throws SecurityAdvisoryException
    {
        Optional<SecurityAdvisory> advisoryOpt = this.securityAdvisoriesManager.loadAdvisory(advisoryReference);
        if (advisoryOpt.isEmpty() || advisoryOpt.get().getAssignee() != null) {
            return false;
        }
        String serializedAssignee = this.externalUserMappingStore.resolveAssignee(advisoryOpt.get().getExternalUsers())
            .map(assignee -> this.userPropertyConverter.serialize(assignee, advisoryReference))
            .orElse(null);
        if (serializedAssignee == null) {
            return false;
        }

        XWikiContext context = this.contextProvider.get();
        try {
            XWikiDocument document = context.getWiki().getDocument(advisoryReference, context).clone();
            BaseObject advisoryObject =
                document.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
            // Check again on the document itself, in case the assignee was set since the advisory was loaded.
            if (StringUtils.isNotBlank(advisoryObject.getLargeStringValue(
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE)))
            {
                return false;
            }
            advisoryObject.setLargeStringValue(
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ASSIGNEE, serializedAssignee);
            DocumentAuthors authors = document.getAuthors();
            authors.setOriginalMetadataAuthor(author);
            authors.setEffectiveMetadataAuthor(author);
            context.getWiki().saveDocument(document, "Set assignee from the external user mapping", true, context);
            return true;
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(
                String.format("Error while setting the assignee of advisory [%s]", advisoryReference), e);
        }
    }
}
