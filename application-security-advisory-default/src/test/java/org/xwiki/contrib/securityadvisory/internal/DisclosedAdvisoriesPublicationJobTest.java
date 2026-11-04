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

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.xwiki.contrib.securityadvisory.SecurityAdvisoryException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.test.LogLevel;
import org.xwiki.test.junit5.LogCaptureExtension;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DisclosedAdvisoriesPublicationJob}.
 *
 * @version $Id$
 */
@ComponentTest
class DisclosedAdvisoriesPublicationJobTest
{
    private static final List<String> SECURITY_SPACE = List.of("SecurityAdvisoryApplication", "SecurityEntries");

    private static final DocumentReference FAILING_ADVISORY =
        new DocumentReference("xwiki", SECURITY_SPACE, "GHSA-failing");

    private static final DocumentReference ADVISORY = new DocumentReference("xwiki", SECURITY_SPACE, "GHSA-test");

    private static final DocumentReference PUBLIC_ADVISORY =
        new DocumentReference("xwiki", List.of("SecurityAdvisoryApplication", "DisclosedEntries"), "GHSA-test");

    @RegisterExtension
    private final LogCaptureExtension logCapture = new LogCaptureExtension(LogLevel.INFO);

    @InjectMockComponents
    private DisclosedAdvisoriesPublicationJob job;

    @MockComponent
    private DisclosedAdvisoryPublisher publisher;

    @Test
    void publishAllEvenAfterAFailure() throws Exception
    {
        when(this.publisher.getUnpublishedDisclosedAdvisories()).thenReturn(List.of(FAILING_ADVISORY, ADVISORY));
        when(this.publisher.publish(FAILING_ADVISORY)).thenThrow(new SecurityAdvisoryException("Publishing failed"));
        when(this.publisher.publish(ADVISORY)).thenReturn(PUBLIC_ADVISORY);

        this.job.runInternal();

        // The failure on the first advisory doesn't prevent the publication of the next one.
        verify(this.publisher).publish(ADVISORY);
        assertEquals("Failed to publish advisory [xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-failing].",
            this.logCapture.getMessage(0));
        assertEquals("Published advisory [xwiki:SecurityAdvisoryApplication.SecurityEntries.GHSA-test] to "
            + "[xwiki:SecurityAdvisoryApplication.DisclosedEntries.GHSA-test].", this.logCapture.getMessage(1));
        assertEquals("Published [1] advisories out of [2] disclosed advisories not published yet.",
            this.logCapture.getMessage(2));
    }
}
