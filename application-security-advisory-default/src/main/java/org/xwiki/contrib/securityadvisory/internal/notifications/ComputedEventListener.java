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
package org.xwiki.contrib.securityadvisory.internal.notifications;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Provider;

import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.contrib.securityadvisory.event.DisclosableComputedEvent;
import org.xwiki.contrib.securityadvisory.event.EmbargoDateComputedEvent;
import org.xwiki.eventstream.RecordableEvent;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.ObservationManager;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

public class ComputedEventListener extends AbstractEventListener
{
    static final String NAME = "SecurityAdvisoryComputedEventListener";

    @Inject
    private SecurityAdvisoryConfiguration securityAdvisoryConfiguration;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private ObservationManager observationManager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    public ComputedEventListener()
    {
        super(NAME, Arrays.asList(new DisclosableComputedEvent(), new EmbargoDateComputedEvent()));
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        SecurityAdvisory securityAdvisory = (SecurityAdvisory) data;
        Set<String> targets = new HashSet<>();
        targets.add(this.entityReferenceSerializer.serialize(securityAdvisory.getAuthor()));
        try {
            targets.add(this.entityReferenceSerializer.serialize(securityAdvisoryConfiguration.getSecurityGroup()));
        } catch (SecurityAdvisoryException e) {
            throw new RuntimeException(e);
        }

        RecordableEvent recordableEvent;
        if (event instanceof DisclosableComputedEvent) {
            recordableEvent = new DisclosableTargetableEvent(targets);
        } else {
            recordableEvent = new EmbargoDateTargetableEvent(targets);
        }
        XWikiContext context = this.contextProvider.get();
        try {
            XWikiDocument document = context.getWiki().getDocument(securityAdvisory.getDocumentReference(), context);
            this.observationManager.notify(recordableEvent,
                "org.xwiki.contrib.security-advisory:application-security-advisory-default", document);
        } catch (XWikiException e) {
            throw new RuntimeException(e);
        }
    }
}
