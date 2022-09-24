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

import java.util.Date;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;

@Component(roles = VersionReleasedManager.class)
@Singleton
public class VersionReleasedManager
{
    private static final String RELEASE_NOTE_CLASS = "ReleaseNotes.Code.ReleaseNoteClass";

    @Inject
    private QueryManager queryManager;

    // TODO: introduce a cache
    public boolean isVersionReleased(String version)
    {
        String statement = String.format("from doc.object(%s) as objRelease where objRelease.released=1 and "
                + "objRelease.version=:version",
            RELEASE_NOTE_CLASS);
        try {
            Query query = this.queryManager.createQuery(statement, Query.XWQL).bindValue("version", version);
            return query.execute().size() > 0;
        } catch (QueryException e) {
            throw new RuntimeException(e);
        }
    }

    public Date getReleaseDate(String version)
    {
        String statement = String.format("select objRelease.date from Document doc, doc.object(%s) as objRelease "
                + "where objRelease.released=1 and objRelease.version=:version",
            RELEASE_NOTE_CLASS);
        try {
            Query query = this.queryManager.createQuery(statement, Query.XWQL).bindValue("version", version);
            // TODO: the returned query execution might be directly a long, but that need to be tested.
            return (Date) query.execute().get(0);
        } catch (QueryException e) {
            throw new RuntimeException(e);
        }
    }
}
