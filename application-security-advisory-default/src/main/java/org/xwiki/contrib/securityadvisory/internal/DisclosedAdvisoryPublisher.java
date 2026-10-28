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
package org.xwiki.contrib.securityadvisory.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.model.document.DocumentAuthors;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.user.UserReference;
import org.xwiki.user.UserReferenceResolver;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;

/**
 * Publish a disclosed advisory in the public data space, so that anyone can view it.
 * <p>
 * The advisory page stored in the security data space keeps its history, its comments and its attachments, which
 * contain information that must remain private. So instead of being moved, the advisory is published as a new page in
 * the public data space holding only the advisory information, and the original page receives a redirect object
 * pointing to the published page. A page holding both the advisory object and a redirect object is thus an original
 * that has been published and must be ignored when looking for advisories.
 *
 * @version $Id$
 * @since 2.3.0
 */
@Component(roles = DisclosedAdvisoryPublisher.class)
@Singleton
public class DisclosedAdvisoryPublisher
{
    /**
     * Reference of the class used by XWiki to redirect the view of a page to another location.
     */
    public static final LocalDocumentReference REDIRECT_CLASS_REFERENCE =
        new LocalDocumentReference("XWiki", "RedirectClass");

    /**
     * Name of the property holding the target of the redirect.
     */
    public static final String REDIRECT_LOCATION = "location";

    private static final String ADVISORY_ACCESS_EXCEPTION = "Error while trying to access the advisory [%s]";

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private SecurityAdvisoryConfiguration configuration;

    @Inject
    private AuthorizationManager authorizationManager;

    @Inject
    private QueryManager queryManager;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    @Named("compactwiki")
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    @Named("document")
    private UserReferenceResolver<DocumentReference> userReferenceResolver;

    /**
     * @param advisoryReference the reference of an advisory page located in the security data space
     * @return the reference of the page where the advisory is published once disclosed
     */
    public DocumentReference getPublicReference(DocumentReference advisoryReference)
    {
        return new DocumentReference(advisoryReference.getName(), this.configuration.getPublicDataSpace());
    }

    /**
     * @param advisoryReference the reference of an advisory page
     * @return {@code true} if the page is located in the public data space
     */
    public boolean isInPublicDataSpace(DocumentReference advisoryReference)
    {
        return Objects.equals(advisoryReference.getLastSpaceReference(), this.configuration.getPublicDataSpace());
    }

    /**
     * @param document a document holding an advisory
     * @return {@code true} if the document is an original advisory page that has already been published
     */
    public boolean isPublishedOriginal(XWikiDocument document)
    {
        return document.getXObject(REDIRECT_CLASS_REFERENCE) != null;
    }

    /**
     * Check if the current user has the rights needed to publish the given advisory: publishing requires to edit the
     * advisory page, to add the redirect, and to edit the public page.
     *
     * @param advisoryReference the reference of the advisory to publish
     * @return {@code true} if the current user is allowed to publish the advisory
     */
    public boolean canPublish(DocumentReference advisoryReference)
    {
        DocumentReference userReference = this.contextProvider.get().getUserReference();
        return this.authorizationManager.hasAccess(Right.EDIT, userReference, advisoryReference)
            && this.authorizationManager.hasAccess(Right.EDIT, userReference, getPublicReference(advisoryReference));
    }

    /**
     * Publish the given advisory in the public data space and mark it as disclosed.
     * <p>
     * The public page is saved first and the original page last, in a single save setting both the disclosed state
     * and the redirect. So if anything fails, the original page keeps its previous state and publishing it again
     * resumes the operation: an existing public page holding the same advisory is reused.
     *
     * @param advisoryReference the reference of the advisory to publish, which must be disclosable or disclosed
     * @return the reference of the published page
     * @throws SecurityAdvisoryException if the current user is not allowed to publish the advisory, if the advisory
     *     cannot be published, or in case of problem to load or save the pages
     */
    public DocumentReference publish(DocumentReference advisoryReference) throws SecurityAdvisoryException
    {
        if (!canPublish(advisoryReference)) {
            throw new SecurityAdvisoryException(
                String.format("The current user is not allowed to publish the advisory [%s].", advisoryReference));
        }

        XWikiContext context = this.contextProvider.get();
        DocumentReference publicReference = getPublicReference(advisoryReference);
        try {
            XWikiDocument original = context.getWiki().getDocument(advisoryReference, context).clone();
            BaseObject originalObject = getPublishableAdvisoryObject(original);

            XWikiDocument publicDocument = context.getWiki().getDocument(publicReference, context);
            if (publicDocument.isNew()) {
                publicDocument = createPublicDocument(original, publicReference, context);
                context.getWiki().saveDocument(publicDocument,
                    String.format("Publish disclosed advisory from [%s]", advisoryReference), context);
            } else if (!isSameAdvisory(originalObject, publicDocument)) {
                throw new SecurityAdvisoryException(String.format(
                    "Cannot publish the advisory [%s]: the page [%s] already exists and holds another advisory.",
                    advisoryReference, publicReference));
            }

            originalObject.setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE,
                SecurityAdvisory.State.DISCLOSED.name());
            BaseObject redirectObject = original.newXObject(REDIRECT_CLASS_REFERENCE, context);
            redirectObject.setStringValue(REDIRECT_LOCATION, this.entityReferenceSerializer.serialize(publicReference));
            context.getWiki().saveDocument(original,
                String.format("Disclosed and published to [%s]", publicReference), context);
        } catch (XWikiException e) {
            throw new SecurityAdvisoryException(String.format(ADVISORY_ACCESS_EXCEPTION, advisoryReference), e);
        }
        return publicReference;
    }

    /**
     * Look for the advisories that are disclosed but not published: they were disclosed before the public data space
     * existed, or imported as already published from an external source.
     *
     * @return the references of the disclosed advisories that are not published yet
     * @throws SecurityAdvisoryException in case of problem to query or load the advisories
     */
    public List<DocumentReference> getUnpublishedDisclosedAdvisories() throws SecurityAdvisoryException
    {
        String statement = String.format("from doc.object(%s) as objAdv where objAdv.%s = :status",
            this.entityReferenceSerializer
                .serialize(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE),
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE);
        XWikiContext context = this.contextProvider.get();
        List<DocumentReference> results = new ArrayList<>();
        try {
            List<String> references = this.queryManager.createQuery(statement, Query.XWQL)
                .bindValue("status", SecurityAdvisory.State.DISCLOSED.name())
                .execute();
            for (String reference : references) {
                DocumentReference documentReference = this.documentReferenceResolver.resolve(reference);
                if (!isInPublicDataSpace(documentReference)
                    && !isPublishedOriginal(context.getWiki().getDocument(documentReference, context))) {
                    results.add(documentReference);
                }
            }
        } catch (QueryException | XWikiException e) {
            throw new SecurityAdvisoryException("Error when retrieving the disclosed advisories to publish", e);
        }
        return results;
    }

    private BaseObject getPublishableAdvisoryObject(XWikiDocument original) throws SecurityAdvisoryException
    {
        DocumentReference advisoryReference = original.getDocumentReference();
        BaseObject advisoryObject =
            original.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        if (advisoryObject == null) {
            throw new SecurityAdvisoryException(
                String.format("The page [%s] does not hold any advisory.", advisoryReference));
        }
        if (isPublishedOriginal(original)) {
            throw new SecurityAdvisoryException(
                String.format("The advisory [%s] is already published.", advisoryReference));
        }
        if (isInPublicDataSpace(advisoryReference)) {
            throw new SecurityAdvisoryException(
                String.format("The advisory [%s] is already located in the public data space.", advisoryReference));
        }
        String state = advisoryObject.getStringValue(
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE);
        if (!SecurityAdvisory.State.DISCLOSABLE.name().equalsIgnoreCase(state)
            && !SecurityAdvisory.State.DISCLOSED.name().equalsIgnoreCase(state)) {
            throw new SecurityAdvisoryException(
                String.format("The advisory [%s] cannot be published in state [%s].", advisoryReference, state));
        }
        return advisoryObject;
    }

    private boolean isSameAdvisory(BaseObject originalObject, XWikiDocument publicDocument)
    {
        BaseObject publicObject =
            publicDocument.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        return publicObject != null && StringUtils.equals(
            originalObject.getStringValue(
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK),
            publicObject.getStringValue(
                SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_ADVISORY_LINK));
    }

    /**
     * Create the public page with the advisory information only: the history, the comments, the attachments and any
     * other object of the original page are not copied, as they might contain information that should remain private.
     */
    private XWikiDocument createPublicDocument(XWikiDocument original, DocumentReference publicReference,
        XWikiContext context) throws XWikiException
    {
        XWikiDocument publicDocument = new XWikiDocument(publicReference);
        publicDocument.setTitle(original.getTitle());
        publicDocument.setSyntax(original.getSyntax());
        publicDocument.setContent(original.getContent());
        publicDocument.setEnforceRequiredRights(original.isEnforceRequiredRights());

        copyObjects(original, publicDocument,
            SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        copyObjects(original, publicDocument, ImpactedPackageClassMandatoryDocumentInitializer.CLASS_REFERENCE);
        publicDocument.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE)
            .setStringValue(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_STATE,
                SecurityAdvisory.State.DISCLOSED.name());

        // The content and the objects keep the authors of the original page: using the current user instead would
        // allow the content written by someone else to be executed with the rights of the user who discloses it.
        DocumentAuthors originalAuthors = original.getAuthors();
        DocumentAuthors publicAuthors = publicDocument.getAuthors();
        UserReference currentUser = this.userReferenceResolver.resolve(context.getUserReference());
        publicAuthors.setContentAuthor(originalAuthors.getContentAuthor());
        publicAuthors.setEffectiveMetadataAuthor(originalAuthors.getEffectiveMetadataAuthor());
        publicAuthors.setOriginalMetadataAuthor(currentUser);
        publicAuthors.setCreator(currentUser);
        return publicDocument;
    }

    private void copyObjects(XWikiDocument source, XWikiDocument target, EntityReference classReference)
        throws XWikiException
    {
        for (BaseObject object : source.getXObjects(classReference)) {
            if (object != null) {
                target.addXObject(object.duplicate(target.getDocumentReference()));
            }
        }
    }
}
