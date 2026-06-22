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

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.metaeffekt.core.security.cvss.CvssVector;
import org.slf4j.Logger;
import org.xwiki.bridge.event.DocumentCreatingEvent;
import org.xwiki.bridge.event.DocumentUpdatingEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.observation.event.AbstractLocalEventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

import static org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVSS;
import static org.xwiki.contrib.securityadvisory.internal.SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.FIELD_CVSS_SCORE;

/**
 * Listener to compute the CVSS score of a security advisory.
 *
 * @version $Id$
 */
@Component
@Singleton
@Named(CVSSComputingListener.NAME)
public class CVSSComputingListener extends AbstractLocalEventListener
{
    static final String NAME = "org.xwiki.contrib.securityadvisory.internal.CVSSComputingListener";

    @Inject
    private Logger logger;

    /**
     * Default constructor.
     */
    public CVSSComputingListener()
    {
        super(NAME, new DocumentUpdatingEvent(), new DocumentCreatingEvent());
    }

    @Override
    public void processLocalEvent(Event event, Object source, Object data)
    {
        if (source instanceof XWikiDocument document) {
            BaseObject securityAdvisoryObject =
                document.getXObject(SecurityAdvisoryApplicationClassMandatoryDocumentInitializer.CLASS_REFERENCE);
            if (securityAdvisoryObject != null) {
                maybeUpdateObject(securityAdvisoryObject);
            }
        }
    }

    private void maybeUpdateObject(BaseObject securityAdvisoryObject)
    {
        String cvssVector = securityAdvisoryObject.getStringValue(FIELD_CVSS);
        double cvssScore = securityAdvisoryObject.getDoubleValue(FIELD_CVSS_SCORE);
        if (StringUtils.isNotBlank(cvssVector)) {
            CvssVector parsedVector = CvssVector.parseVector(cvssVector);
            if (parsedVector != null) {
                double computedScore = parsedVector.getBaseScore();
                if (computedScore != cvssScore) {
                    securityAdvisoryObject.setDoubleValue(FIELD_CVSS_SCORE, computedScore);
                }
            } else {
                this.logger.error("Vector [{}] cannot be parsed as CVSS vector in [{}].", cvssVector,
                    securityAdvisoryObject.getOwnerDocument().getDocumentReference());
            }
        }
    }
}
