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
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.securityadvisory.SecurityAdvisory;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryConfiguration;
import org.xwiki.contrib.securityadvisory.event.AdvisoryStateChangedEvent;
import org.xwiki.contrib.securityadvisory.event.EmbargoDateComputedEvent;
import org.xwiki.eventstream.RecordableEvent;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.ObservationManager;
import org.xwiki.observation.event.Event;
import org.xwiki.user.UserReferenceSerializer;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Listener of {@link AdvisoryStateChangedEvent} and {@link EmbargoDateComputedEvent} in charge of sending the
 * appropriate recordable events.
 *
 * @version $Id$
 * @since 1.0
 */
@Component
@Named(ComputedEventListener.NAME)
@Singleton
public class ComputedEventListener extends AbstractEventListener
{
    static final String NAME = "SecurityAdvisoryComputedEventListener";

    @Inject
    private SecurityAdvisoryConfiguration securityAdvisoryConfiguration;

    @Inject
    private UserReferenceSerializer<String> userReferenceSerializer;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    @Inject
    private ObservationManager observationManager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public ComputedEventListener()
    {
        super(NAME, Arrays.asList(new AdvisoryStateChangedEvent(), new EmbargoDateComputedEvent()));
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        SecurityAdvisory securityAdvisory = (SecurityAdvisory) source;
        Set<String> targets = new HashSet<>();
        targets.add(this.userReferenceSerializer.serialize(securityAdvisory.getAuthor()));
        targets.add(this.entityReferenceSerializer.serialize(securityAdvisoryConfiguration.getSecurityGroup()));

        RecordableEvent recordableEvent;
        if (event instanceof AdvisoryStateChangedEvent) {
            recordableEvent = getRecordableEventForStateChangedEvent(data, targets);
        } else {
            recordableEvent = new EmbargoDateTargetableEvent(targets);
        }
        if (recordableEvent != null) {
            XWikiContext context = this.contextProvider.get();
            try {
                XWikiDocument document = context.getWiki().getDocument(securityAdvisory.getHolderReference(), context);
                this.observationManager.notify(recordableEvent,
                    "org.xwiki.contrib.security-advisory:application-security-advisory-default", document);
            } catch (XWikiException e) {
                this.logger.error("Error while getting the document [{}] for sending advisory notifications",
                    securityAdvisory.getHolderReference(), e);
            }
        }
    }

    private RecordableEvent getRecordableEventForStateChangedEvent(Object data, Set<String> targets)
    {
        RecordableEvent result = null;
        if (data instanceof Pair) {
            Pair<SecurityAdvisory.State, SecurityAdvisory.State> states =
                (Pair<SecurityAdvisory.State, SecurityAdvisory.State>) data;
            SecurityAdvisory.State newState = states.getRight();
            if (newState == SecurityAdvisory.State.DISCLOSABLE) {
                result = new DisclosableTargetableEvent(targets);
            } else if (newState == SecurityAdvisory.State.ANNOUNCED) {
                result = new AnnouncedAdvisoryTargetableEvent(targets);
            }
        } else {
            this.logger.error("Unexpected data sent for AdvisoryStateChangedEvent: [{}]", data);
        }
        return result;
    }
}
