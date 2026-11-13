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
package org.xwiki.contrib.securityadvisory.event;

import org.xwiki.observation.event.BeginEvent;

/**
 * Event triggered before the document holding an imported advisory is saved with the imported data. It's followed by
 * an {@link AdvisoryImportedEvent} once the document is saved, so that a listener can tell, with
 * {@link org.xwiki.observation.ObservationContext#isIn(BeginEvent)}, whether a document is saved by an import.
 * The source of the event is the imported {@link org.xwiki.contrib.securityadvisory.SecurityAdvisory}, and its data
 * is the {@link com.xpn.xwiki.XWikiContext}.
 *
 * @version $Id$
 * @since 2.3.1
 */
public class AdvisoryImportingEvent implements BeginEvent
{
    @Override
    public boolean matches(Object otherEvent)
    {
        return otherEvent instanceof AdvisoryImportingEvent;
    }
}
