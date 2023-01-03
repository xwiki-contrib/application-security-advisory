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

import java.util.Collections;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.internal.event.XObjectUpdatedEvent;
import com.xpn.xwiki.objects.BaseObjectReference;

/**
 * Listener for changes in release note xobjects to trigger embargo date computation.
 *
 * @version $Id$
 * @since 1.0
 */
@Component
@Singleton
@Named(VersionReleasedListener.NAME)
public class VersionReleasedListener extends AbstractEventListener
{
    static final String NAME = "VersionReleasedListener";

    @Inject
    private SecurityAdvisoriesManager securityAdvisoriesManager;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public VersionReleasedListener()
    {
        super(NAME, Collections.singletonList(
            new XObjectUpdatedEvent(BaseObjectReference.any(VersionReleasedManager.RELEASE_NOTE_CLASS))));
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // FIXME: This should be optimized to only compute the date for the newly released version.
        try {
            this.securityAdvisoriesManager.computeEmbargoDates();
        } catch (SecurityAdvisoryException e) {
            this.logger.error("Error when computing embargo dates", e);
        }
    }
}
