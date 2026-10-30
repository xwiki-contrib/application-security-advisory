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

import org.xwiki.job.AbstractRequest;
import org.xwiki.model.reference.DocumentReference;

/**
 * The request used to configure the {@link AssigneeResolutionJob}.
 *
 * @version $Id$
 * @since 2.3.0
 */
public class AssigneeResolutionRequest extends AbstractRequest
{
    private static final long serialVersionUID = 1L;

    private static final String PROPERTY_AUTHOR = "author";

    /**
     * Default constructor.
     */
    public AssigneeResolutionRequest()
    {
        // Keep the job log isolated from the standard output: it is meant to be displayed to the administrator through
        // the job status in the administration.
        setStatusLogIsolated(true);
    }

    /**
     * @param id the identifier used to access the job
     * @param author the reference of the user to record as author of the changes made on the advisories
     */
    public AssigneeResolutionRequest(List<String> id, DocumentReference author)
    {
        this();
        setId(id);
        setProperty(PROPERTY_AUTHOR, author);
    }

    /**
     * @return the reference of the user to record as author of the changes made on the advisories
     */
    public DocumentReference getAuthor()
    {
        return getProperty(PROPERTY_AUTHOR);
    }
}
