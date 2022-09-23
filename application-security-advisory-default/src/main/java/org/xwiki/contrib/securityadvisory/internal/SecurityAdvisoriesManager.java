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

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryExecutor;
import org.xwiki.query.QueryManager;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

@Component(roles = SecurityAdvisoriesManager.class)
@Singleton
public class SecurityAdvisoriesManager
{
    private static final String SECURITY_ADVISORY_CLASS =
        "SecurityAdvisoryApplication.Code.SecurityAdvisoryApplicationClass";

    @Inject
    private QueryManager queryManager;

    @Inject
    private QueryExecutor queryExecutor;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    public List<SecurityAdvisory> getAdvisoriesWithStatus(String status, boolean computeEmbargoDate)
    {
        String statement = String.format("where doc.object(%1$s).status = :status and "
            + "doc.object(%1$s).computeEmbargoDate = :computeEmbargoDate",
            SECURITY_ADVISORY_CLASS);

        if (computeEmbargoDate) {
            statement += " and embargoDate = ''";
        } else {
            statement += " and embargoDate != ''";
        }

        try {
            Query query = this.queryManager.createQuery(statement, Query.XWQL)
                .bindValue("status", status)
                .bindValue("computeEmbargoDate", computeEmbargoDate);
            List<SecurityAdvisory> results = new ArrayList<>();
            for (Object reference : this.queryExecutor.execute(query)) {
                DocumentReference documentReference = this.documentReferenceResolver.resolve(String.valueOf(reference));
                SecurityAdvisory advisory = this.getAdvisoryFromDocument(documentReference);
                if (advisory != null) {
                    results.add(advisory);
                }
            }
            return results;
        } catch (QueryException e) {
            throw new RuntimeException(e);
        }
    }

    public SecurityAdvisory getAdvisoryFromDocument(DocumentReference documentReference)
    {
        XWikiContext context = this.contextProvider.get();
        try {
            XWikiDocument document = context.getWiki().getDocument(documentReference, context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                SecurityAdvisory result = new SecurityAdvisory(documentReference);
                result.setAffectedVersions(xObject.getListValue("affectedVersions"))
                    .setPatchedVersions(xObject.getListValue("patchedVersions"))
                    .setEmbargoDate(xObject.getDateValue("embargoDate"))
                    .setComputeEmbargoDate(xObject.getIntValue("computeEmbargoDate") == 1)
                    .setAuthor(document.getAuthorReference());
                return result;
            }
        } catch (XWikiException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    public void saveEmbargoDate(SecurityAdvisory securityAdvisory)
    {
        XWikiContext context = this.contextProvider.get();
        try {
            XWikiDocument document = context.getWiki().getDocument(securityAdvisory.getDocumentReference(), context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                xObject.setDateValue("embargoDate", securityAdvisory.getEmbargoDate());
                context.getWiki().saveDocument(document, "Set embargo date", context);
            } else {
                // TODO: throw some exception
            }
        } catch (XWikiException e) {
            throw new RuntimeException(e);
        }
    }

    public void saveDisablosable(SecurityAdvisory securityAdvisory)
    {
        XWikiContext context = this.contextProvider.get();
        try {
            XWikiDocument document = context.getWiki().getDocument(securityAdvisory.getDocumentReference(), context);
            BaseObject xObject = document.getXObject(this.documentReferenceResolver.resolve(SECURITY_ADVISORY_CLASS));
            if (xObject != null) {
                xObject.setStringValue("status", "disclosable");
                context.getWiki().saveDocument(document, "Set disclosable status", context);
            } else {
                // TODO: throw some exception
            }
        } catch (XWikiException e) {
            throw new RuntimeException(e);
        }
    }
}
