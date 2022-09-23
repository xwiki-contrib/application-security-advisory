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
package org.xwiki.contrib.securityadvisory;

import java.util.Date;
import java.util.List;

import org.xwiki.model.reference.DocumentReference;

public class SecurityAdvisory
{
    private final DocumentReference documentReference;
    private List<String> affectedVersions;
    private List<String> patchedVersions;
    private Date embargoDate;
    private boolean computeEmbargoDate;

    private DocumentReference author;

    public SecurityAdvisory(DocumentReference documentReference)
    {
        this.documentReference = documentReference;
    }

    public DocumentReference getDocumentReference()
    {
        return documentReference;
    }

    public List<String> getAffectedVersions()
    {
        return affectedVersions;
    }

    public SecurityAdvisory setAffectedVersions(List<String> affectedVersions)
    {
        this.affectedVersions = affectedVersions;
        return this;
    }

    public List<String> getPatchedVersions()
    {
        return patchedVersions;
    }

    public SecurityAdvisory setPatchedVersions(List<String> patchedVersions)
    {
        this.patchedVersions = patchedVersions;
        return this;
    }

    public Date getEmbargoDate()
    {
        return embargoDate;
    }

    public SecurityAdvisory setEmbargoDate(Date embargoDate)
    {
        this.embargoDate = embargoDate;
        return this;
    }

    public boolean isComputeEmbargoDate()
    {
        return computeEmbargoDate;
    }

    public SecurityAdvisory setComputeEmbargoDate(boolean computeEmbargoDate)
    {
        this.computeEmbargoDate = computeEmbargoDate;
        return this;
    }

    public DocumentReference getAuthor()
    {
        return author;
    }

    public SecurityAdvisory setAuthor(DocumentReference author)
    {
        this.author = author;
        return this;
    }
}
